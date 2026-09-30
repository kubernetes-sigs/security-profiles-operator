/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package artifact

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact/artifactfakes"
)

func TestMatchesAnything(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		pattern  string
		expected bool
	}{
		{pattern: "", expected: true},
		{pattern: ".*", expected: true},
		{pattern: " .* ", expected: true},
		{pattern: ".+", expected: true},
		{pattern: "^.*$", expected: true},
		{pattern: "^.+$", expected: true},
		{pattern: "(.*)", expected: true},
		{pattern: "(.+)", expected: true},
		{pattern: "^", expected: true},
		{pattern: "$", expected: true},
		{pattern: "^me@example\\.com$", expected: false},
		{pattern: "^https://accounts\\.google\\.com$", expected: false},
		{pattern: OfficialSignerIdentityRegexp, expected: false},
		// Not recognised as unconstrained, which only means "not obviously".
		{pattern: ".*@.*", expected: false},
		{pattern: "^.*.*$", expected: false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, matchesAnything(tc.pattern))
		})
	}
}

func TestIsOfficialArtifact(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		image    string
		expected bool
	}{
		{image: "registry.k8s.io/security-profiles-operator/base/runc:v1.5.1", expected: true},
		{image: "registry.k8s.io/security-profiles-operator/base/runc@sha256:abc", expected: true},
		{image: "us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/base/crun:latest", expected: true},
		{image: "registry.k8s.io/security-profiles-operator", expected: false},
		{image: "registry.k8s.io/other/base/runc:v1.5.1", expected: false},
		{image: "registry.example.com/registry.k8s.io/security-profiles-operator/base/runc:v1", expected: false},
		{image: "", expected: false},
	} {
		t.Run(tc.image, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, IsOfficialArtifact(tc.image))
		})
	}
}

func TestHasUnconstrainedSigner(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		opts     PullOptions
		expected bool
	}{
		{name: "empty", expected: true},
		{
			name:     "defaults of spoc and the SPOD",
			opts:     PullOptions{AllowedIdentityRegexp: ".*", AllowedOidcIssuerRegexp: ".*"},
			expected: true,
		},
		{
			name:     "anchored any",
			opts:     PullOptions{AllowedIdentityRegexp: "^.*$", AllowedOidcIssuerRegexp: "^.*$"},
			expected: true,
		},
		{
			name:     "identity only",
			opts:     PullOptions{AllowedIdentityRegexp: "^me$", AllowedOidcIssuerRegexp: ".*"},
			expected: true,
		},
		{
			name:     "issuer only",
			opts:     PullOptions{AllowedOidcIssuerRegexp: "^https://issuer$"},
			expected: true,
		},
		{
			name: "identity and issuer",
			opts: PullOptions{
				AllowedIdentityRegexp:   "^me$",
				AllowedOidcIssuerRegexp: "^https://issuer$",
			},
			expected: false,
		},
		{
			name: "official signers",
			opts: PullOptions{
				AllowedIdentityRegexp:   OfficialSignerIdentityRegexp,
				AllowedOidcIssuerRegexp: OfficialSignerOidcIssuerRegexp,
			},
			expected: false,
		},
		{
			name:     "key",
			opts:     PullOptions{KeyRef: "cosign.pub"},
			expected: false,
		},
		{
			name:     "key with any identity",
			opts:     PullOptions{KeyRef: "cosign.pub", AllowedIdentityRegexp: ".*"},
			expected: false,
		},
		{
			name:     "exact identity with any issuer",
			opts:     PullOptions{CertIdentity: "me@example.com", AllowedOidcIssuerRegexp: ".*"},
			expected: true,
		},
		{
			name:     "exact identity and issuer",
			opts:     PullOptions{CertIdentity: "me@example.com", CertOidcIssuer: "https://issuer"},
			expected: false,
		},
		{
			name:     "exact identity and issuer regexp",
			opts:     PullOptions{CertIdentity: "me@example.com", AllowedOidcIssuerRegexp: "^https://issuer$"},
			expected: false,
		},
		{
			name:     "exact issuer with any identity",
			opts:     PullOptions{CertOidcIssuer: "https://issuer", AllowedIdentityRegexp: ".*"},
			expected: true,
		},
		{
			name:     "exact issuer and identity regexp",
			opts:     PullOptions{CertOidcIssuer: "https://issuer", AllowedIdentityRegexp: "^me$"},
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, tc.opts.hasUnconstrainedSigner())
		})
	}
}

func TestWithDefaultSigner(t *testing.T) {
	t.Parallel()

	const (
		official = "registry.k8s.io/security-profiles-operator/base/runc:v1.5.1"
		other    = "registry.example.com/profiles/runc:v1.5.1"
	)

	for _, tc := range []struct {
		name     string
		image    string
		opts     PullOptions
		expected PullOptions
	}{
		{
			name:  "official with empty regexps",
			image: official,
			expected: PullOptions{
				AllowedIdentityRegexp:   OfficialSignerIdentityRegexp,
				AllowedOidcIssuerRegexp: OfficialSignerOidcIssuerRegexp,
			},
		},
		{
			name:  "official with the default regexps",
			image: official,
			opts:  PullOptions{AllowedIdentityRegexp: ".*", AllowedOidcIssuerRegexp: ".*"},
			expected: PullOptions{
				AllowedIdentityRegexp:   OfficialSignerIdentityRegexp,
				AllowedOidcIssuerRegexp: OfficialSignerOidcIssuerRegexp,
			},
		},
		{
			name:  "official with anchored any regexps",
			image: official,
			opts:  PullOptions{AllowedIdentityRegexp: "^.*$", AllowedOidcIssuerRegexp: "^.*$"},
			// Only the shipped default is replaced, every other spelling
			// counts as a choice of the caller.
			expected: PullOptions{AllowedIdentityRegexp: "^.*$", AllowedOidcIssuerRegexp: "^.*$"},
		},
		{
			name:     "official with own identity",
			image:    official,
			opts:     PullOptions{AllowedIdentityRegexp: "^me$"},
			expected: PullOptions{AllowedIdentityRegexp: "^me$"},
		},
		{
			name:     "official with own issuer",
			image:    official,
			opts:     PullOptions{AllowedIdentityRegexp: ".*", AllowedOidcIssuerRegexp: "^https://issuer$"},
			expected: PullOptions{AllowedIdentityRegexp: ".*", AllowedOidcIssuerRegexp: "^https://issuer$"},
		},
		{
			name:     "official with key",
			image:    official,
			opts:     PullOptions{KeyRef: "cosign.pub", AllowedIdentityRegexp: ".*"},
			expected: PullOptions{KeyRef: "cosign.pub", AllowedIdentityRegexp: ".*"},
		},
		{
			// The issuer stays pinned to the official one.
			name:  "official with exact identity",
			image: official,
			opts:  PullOptions{CertIdentity: "me@example.com"},
			expected: PullOptions{
				CertIdentity:            "me@example.com",
				AllowedOidcIssuerRegexp: OfficialSignerOidcIssuerRegexp,
			},
		},
		{
			// The identity stays pinned to the official one.
			name:  "official with exact issuer",
			image: official,
			opts:  PullOptions{CertOidcIssuer: "https://issuer", AllowedOidcIssuerRegexp: ".*"},
			expected: PullOptions{
				CertOidcIssuer:          "https://issuer",
				AllowedIdentityRegexp:   OfficialSignerIdentityRegexp,
				AllowedOidcIssuerRegexp: ".*",
			},
		},
		{
			name:     "official with exact identity and issuer",
			image:    official,
			opts:     PullOptions{CertIdentity: "me@example.com", CertOidcIssuer: "https://issuer"},
			expected: PullOptions{CertIdentity: "me@example.com", CertOidcIssuer: "https://issuer"},
		},
		{
			name:  "official with exact issuer and own identity regexp",
			image: official,
			opts:  PullOptions{CertOidcIssuer: "https://issuer", AllowedIdentityRegexp: "^me$"},
			expected: PullOptions{
				CertOidcIssuer:        "https://issuer",
				AllowedIdentityRegexp: "^me$",
			},
		},
		{
			name:     "other with empty regexps",
			image:    other,
			expected: PullOptions{AllowedIdentityRegexp: ".*", AllowedOidcIssuerRegexp: ".*"},
		},
		{
			name:     "other with own signer",
			image:    other,
			opts:     PullOptions{AllowedIdentityRegexp: "^me$", AllowedOidcIssuerRegexp: "^https://issuer$"},
			expected: PullOptions{AllowedIdentityRegexp: "^me$", AllowedOidcIssuerRegexp: "^https://issuer$"},
		},
		{
			name:  "other options are kept",
			image: other,
			opts: PullOptions{
				DisableSignatureVerification: true,
				PlainHTTP:                    true,
				TrustedRootPath:              "root.json",
				Offline:                      true,
				MaxBlobSize:                  1,
			},
			expected: PullOptions{
				DisableSignatureVerification: true,
				PlainHTTP:                    true,
				AllowedIdentityRegexp:        ".*",
				AllowedOidcIssuerRegexp:      ".*",
				TrustedRootPath:              "root.json",
				Offline:                      true,
				MaxBlobSize:                  1,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.opts
			require.Equal(t, &tc.expected, opts.withDefaultSigner(tc.image))
			require.Equal(t, tc.opts, opts, "the options must not be modified in place")
		})
	}
}

func TestCertificateIdentity(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                     string
		opts                     PullOptions
		identity, identityRegexp string
		issuer, issuerRegexp     string
	}{
		{
			name:           "regexps",
			opts:           PullOptions{AllowedIdentityRegexp: "^me$", AllowedOidcIssuerRegexp: "^https://issuer$"},
			identityRegexp: "^me$",
			issuerRegexp:   "^https://issuer$",
		},
		{
			name:           "default regexps",
			identityRegexp: ".*",
			issuerRegexp:   ".*",
		},
		{
			// An exact value replaces its regexp, like cosign requires.
			name: "exact identity and issuer",
			opts: PullOptions{
				AllowedIdentityRegexp:   "^me$",
				AllowedOidcIssuerRegexp: "^https://issuer$",
				CertIdentity:            "me@example.com",
				CertOidcIssuer:          "https://issuer",
			},
			identity: "me@example.com",
			issuer:   "https://issuer",
		},
		{
			name: "exact identity",
			opts: PullOptions{
				AllowedIdentityRegexp:   "^me$",
				AllowedOidcIssuerRegexp: "^https://issuer$",
				CertIdentity:            "me@example.com",
			},
			identity:     "me@example.com",
			issuerRegexp: "^https://issuer$",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			identity, err := tc.opts.certificateIdentity()
			require.NoError(t, err)
			require.Equal(t, tc.identity, identity.SubjectAlternativeName.SubjectAlternativeName)
			require.Equal(t, tc.identityRegexp, identity.SubjectAlternativeName.Regexp.String())
			require.Equal(t, tc.issuer, identity.Issuer.Issuer)
			require.Equal(t, tc.issuerRegexp, identity.Issuer.Regexp.String())
		})
	}

	_, err := (&PullOptions{AllowedIdentityRegexp: "("}).certificateIdentity()
	require.ErrorContains(t, err, "identity regexp")

	_, err = (&PullOptions{AllowedOidcIssuerRegexp: "("}).certificateIdentity()
	require.ErrorContains(t, err, "issuer regexp")
}

// TestPullVerifyOptions verifies that the pull options reach the signature
// verification.
func TestPullVerifyOptions(t *testing.T) {
	t.Parallel()

	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.NoError(t, err)

	pull := func(t *testing.T, opts *PullOptions) *artifactfakes.FakeImpl {
		t.Helper()

		mock := &artifactfakes.FakeImpl{}
		mock.NewRepositoryReturns(&remote.Repository{}, nil)
		mock.ResolveRepositoryReturns(testSubject(), nil)
		mock.ParseReferenceReturns(testRef, nil)
		mock.ReadProfileReturns(&seccompprofileapi.SeccompProfile{}, nil)
		mock.ReadFileReturns([]byte(testPublicKey()), nil)
		stubProfile(mock, "")

		sut := New(logr.Discard())
		sut.impl = mock

		_, err := sut.Pull(t.Context(), "registry.example.com/profile:v1", "", "", nil, opts)
		require.NoError(t, err)
		require.Equal(t, 1, mock.VerifyEntityCallCount())

		return mock
	}

	t.Run("key", func(t *testing.T) {
		t.Parallel()

		mock := pull(t, &PullOptions{
			KeyRef:                  "cosign.pub",
			AllowedIdentityRegexp:   ".*",
			AllowedOidcIssuerRegexp: ".*",
			TrustedRootPath:         "root.json",
			Offline:                 true,
		})

		require.Equal(t, 1, mock.ReadFileCallCount())
		require.Equal(t, "cosign.pub", mock.ReadFileArgsForCall(0))

		_, trustedRoot, offline := mock.TrustedMaterialArgsForCall(0)
		require.Equal(t, "root.json", trustedRoot)
		require.True(t, offline)

		// A key signature carries no certificate identity to check, the key
		// of the trusted material verifies it.
		_, material, _, _, identity := mock.VerifyEntityArgsForCall(0)
		require.Nil(t, identity)

		verifier, err := material.PublicKeyVerifier("")
		require.NoError(t, err)
		require.NotNil(t, verifier)
	})

	t.Run("exact identity and issuer", func(t *testing.T) {
		t.Parallel()

		mock := pull(t, &PullOptions{
			CertIdentity:            "me@example.com",
			CertOidcIssuer:          "https://issuer",
			AllowedIdentityRegexp:   ".*",
			AllowedOidcIssuerRegexp: ".*",
		})

		require.Zero(t, mock.ReadFileCallCount())

		_, trustedRoot, offline := mock.TrustedMaterialArgsForCall(0)
		require.Empty(t, trustedRoot)
		require.False(t, offline)

		_, _, _, _, identity := mock.VerifyEntityArgsForCall(0)
		require.NotNil(t, identity)
		require.Equal(t, "me@example.com", identity.SubjectAlternativeName.SubjectAlternativeName)
		require.Equal(t, "https://issuer", identity.Issuer.Issuer)
		require.Empty(t, identity.SubjectAlternativeName.Regexp.String())
		require.Empty(t, identity.Issuer.Regexp.String())
	})

	t.Run("regexps", func(t *testing.T) {
		t.Parallel()

		mock := pull(t, &PullOptions{
			AllowedIdentityRegexp:   "^me$",
			AllowedOidcIssuerRegexp: "^https://issuer$",
		})

		_, _, _, _, identity := mock.VerifyEntityArgsForCall(0)
		require.NotNil(t, identity)
		require.Equal(t, "^me$", identity.SubjectAlternativeName.Regexp.String())
		require.Equal(t, "^https://issuer$", identity.Issuer.Regexp.String())
		require.Empty(t, identity.SubjectAlternativeName.SubjectAlternativeName)
		require.Empty(t, identity.Issuer.Issuer)
	})

	t.Run("invalid key", func(t *testing.T) {
		t.Parallel()

		mock := &artifactfakes.FakeImpl{}
		mock.NewRepositoryReturns(&remote.Repository{}, nil)
		mock.ResolveRepositoryReturns(testSubject(), nil)
		mock.ParseReferenceReturns(testRef, nil)
		mock.ReadFileReturns(nil, errTest)
		stubProfile(mock, "")

		sut := New(logr.Discard())
		sut.impl = mock

		_, err := sut.Pull(
			t.Context(),
			"registry.example.com/profile:v1",
			"",
			"",
			nil,
			&PullOptions{KeyRef: "cosign.pub"},
		)
		require.ErrorIs(t, err, errTest)
		require.Zero(t, mock.VerifyEntityCallCount())
	})
}

// testPublicKey is a PEM encoded public key.
var testPublicKey = sync.OnceValue(func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	raw, err := cryptoutils.MarshalPublicKeyToPEM(key.Public())
	if err != nil {
		panic(err)
	}

	return string(raw)
})

// TestPullNoticesCustomSignerForOfficialArtifact asserts that a custom signer
// or trusted root still applies to an official artifact, which the caller asked
// for explicitly, but that a notice tells that it replaces the official signer.
func TestPullNoticesCustomSignerForOfficialArtifact(t *testing.T) {
	t.Parallel()

	const (
		official = "registry.k8s.io/security-profiles-operator/base/runc:v1"
		private  = "registry.example.com/base/runc:v1"
		notice   = "custom signer or trusted root"
	)

	for _, tc := range []struct {
		name       string
		image      string
		opts       PullOptions
		wantNotice bool
	}{
		{name: "official with key", image: official, opts: PullOptions{KeyRef: "cosign.pub"}, wantNotice: true},
		{
			name:       "official with identity",
			image:      official,
			opts:       PullOptions{CertIdentity: "someone@example.com"},
			wantNotice: true,
		},
		{
			name:       "official with trusted root",
			image:      official,
			opts:       PullOptions{TrustedRootPath: "root.json"},
			wantNotice: true,
		},
		{name: "official with default signer", image: official},
		{
			name:  "official without verification",
			image: official,
			opts:  PullOptions{KeyRef: "cosign.pub", DisableSignatureVerification: true},
		},
		{name: "private with key", image: private, opts: PullOptions{KeyRef: "cosign.pub"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logs bytes.Buffer

			mock := &artifactfakes.FakeImpl{}
			mock.ParseReferenceReturns(nil, errTest)

			sut := New(funcr.New(func(prefix, args string) {
				logs.WriteString(prefix + args + "\n")
			}, funcr.Options{}))
			sut.impl = mock

			_, err := sut.Pull(t.Context(), tc.image, "", "", nil, &tc.opts)
			require.ErrorIs(t, err, errTest)

			if tc.wantNotice {
				require.Contains(t, logs.String(), notice)
			} else {
				require.NotContains(t, logs.String(), notice)
			}
		})
	}
}
