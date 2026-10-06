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

package seccompprofile

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile/seccompprofilefakes"
)

const (
	testOperatorNamespace = "spo"
	testPublicKey         = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"
	testTrustedRoot       = `{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`
)

// pulledOptions records the pull options while the pull runs.
type pulledOptions struct {
	opts artifact.PullOptions
}

func newSignatureTestReconciler(
	t *testing.T, sv *spodapi.SPODSignatureVerification, disable bool,
) (*Reconciler, *seccompprofilefakes.FakeImpl, *pulledOptions) {
	t.Helper()

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	spod.Spec.Security.SignatureVerification = sv
	spod.Spec.Security.DisableOCIArtifactSignatureVerification = &disable

	pulled := &pulledOptions{}

	mock := &seccompprofilefakes.FakeImpl{}
	mock.GetSPODReturns(spod, nil)
	mock.PullResultTypeReturns(artifact.PullResultTypeSeccompProfile)
	mock.PullResultSeccompProfileReturns(&seccompprofileapi.SeccompProfile{})
	mock.PullStub = func(
		_ context.Context, _ logr.Logger, _, _, _ string, _ *v1.Platform, opts *artifact.PullOptions,
	) (*artifact.PullResult, error) {
		pulled.opts = *opts

		return &artifact.PullResult{}, nil
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "cosign", Namespace: testOperatorNamespace},
				Data:       map[string][]byte{"cosign.pub": []byte(testPublicKey)},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "sigstore", Namespace: testOperatorNamespace},
				Data:       map[string]string{"trusted_root.json": testTrustedRoot},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "binary", Namespace: testOperatorNamespace},
				BinaryData: map[string][]byte{"root": []byte(testTrustedRoot)},
			},
			// The same names in another namespace must not be used.
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "default"},
				Data:       map[string][]byte{"cosign.pub": []byte(testPublicKey)},
			},
		).
		Build()

	sut, ok := NewController().(*Reconciler)
	require.True(t, ok)

	sut.impl = mock
	sut.metrics = metrics.New()
	sut.record = events.NewFakeRecorder(10)
	sut.reader = cli
	sut.namespace = testOperatorNamespace

	return sut, mock, pulled
}

func baseProfileUser() *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "default"},
		Spec: seccompprofileapi.SeccompProfileSpec{
			BaseProfileName: config.OCIProfilePrefix + "registry/base:v1",
		},
	}
}

func TestPullBaseProfileSignatureVerification(t *testing.T) {
	t.Parallel()

	const officialImage = "registry.k8s.io/security-profiles-operator/base/runc:v1"

	customSigner := &spodapi.SPODSignatureVerification{
		AllowedIdentity:   "someone@example.com",
		AllowedOidcIssuer: "https://issuer.example.com",
		PublicKeySecretRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "cosign"},
			Key:                  "cosign.pub",
		},
		TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
			Key:                  "trusted_root.json",
		},
	}

	for _, tc := range []struct {
		name            string
		image           string
		sv              *spodapi.SPODSignatureVerification
		disable         bool
		wantOfficial    bool
		wantIdentity    string
		wantIssuer      string
		wantOffline     bool
		wantKey         string
		wantTrustedRoot string
		wantErr         string
	}{
		{
			name: "not configured",
		},
		{
			name: "exact identity and issuer",
			sv: &spodapi.SPODSignatureVerification{
				AllowedIdentity:   "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main",
				AllowedOidcIssuer: "https://token.actions.githubusercontent.com",
			},
			wantIdentity: "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main",
			wantIssuer:   "https://token.actions.githubusercontent.com",
		},
		{
			name: "offline with trusted root",
			sv: &spodapi.SPODSignatureVerification{
				Offline: new(true),
				TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
					Key:                  "trusted_root.json",
				},
			},
			wantOffline:     true,
			wantTrustedRoot: testTrustedRoot,
		},
		{
			// Rejected by the API server, but not by every version.
			name:    "offline without trusted root",
			sv:      &spodapi.SPODSignatureVerification{Offline: new(true)},
			wantErr: errOfflineWithoutTrustedRoot.Error(),
		},
		{
			// The trusted root applies, the signer stays the official one.
			name:            "official base profile keeps the official signer",
			image:           officialImage,
			sv:              customSigner,
			wantOfficial:    true,
			wantTrustedRoot: testTrustedRoot,
		},
		{
			name:  "official base profile ignores the key and the identity",
			image: officialImage,
			sv: &spodapi.SPODSignatureVerification{
				AllowedIdentity: "someone@example.com",
				PublicKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "missing"},
					Key:                  "cosign.pub",
				},
			},
			wantOfficial: true,
		},
		{
			// Air-gapped clusters verify the official base profiles against
			// the trusted root of the ConfigMap.
			name:  "official base profile offline with trusted root",
			image: officialImage,
			sv: &spodapi.SPODSignatureVerification{
				Offline: new(true),
				TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
					Key:                  "trusted_root.json",
				},
			},
			wantOfficial:    true,
			wantOffline:     true,
			wantTrustedRoot: testTrustedRoot,
		},
		{
			// Settings which cannot be used are ignored for the official
			// base profiles, like before the trusted root applied to them.
			name:         "official base profile ignores offline without trusted root",
			image:        officialImage,
			sv:           &spodapi.SPODSignatureVerification{Offline: new(true)},
			wantOfficial: true,
		},
		{
			name:  "official base profile ignores a missing trusted root",
			image: officialImage,
			sv: &spodapi.SPODSignatureVerification{
				Offline: new(true),
				TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
					Key:                  "missing",
				},
			},
			wantOfficial: true,
		},
		{
			name:            "private base profile uses the custom signer",
			sv:              customSigner,
			wantIdentity:    "someone@example.com",
			wantIssuer:      "https://issuer.example.com",
			wantKey:         testPublicKey,
			wantTrustedRoot: testTrustedRoot,
		},
		{
			name: "public key and trusted root",
			sv: &spodapi.SPODSignatureVerification{
				PublicKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "cosign"},
					Key:                  "cosign.pub",
				},
				TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
					Key:                  "trusted_root.json",
				},
			},
			wantKey:         testPublicKey,
			wantTrustedRoot: testTrustedRoot,
		},
		{
			name: "trusted root from binary data",
			sv: &spodapi.SPODSignatureVerification{
				TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "binary"},
					Key:                  "root",
				},
			},
			wantTrustedRoot: testTrustedRoot,
		},
		{
			name: "ignored while verification is disabled",
			sv: &spodapi.SPODSignatureVerification{
				AllowedIdentity: "someone",
				PublicKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "missing"},
					Key:                  "cosign.pub",
				},
			},
			disable: true,
		},
		{
			name: "missing Secret",
			sv: &spodapi.SPODSignatureVerification{
				PublicKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "other"},
					Key:                  "cosign.pub",
				},
			},
			wantErr: "getting the public key Secret spo/other",
		},
		{
			name: "missing Secret key",
			sv: &spodapi.SPODSignatureVerification{
				PublicKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "cosign"},
					Key:                  "missing",
				},
			},
			wantErr: errMissingKey.Error(),
		},
		{
			name: "missing ConfigMap key",
			sv: &spodapi.SPODSignatureVerification{
				PublicKeySecretRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "cosign"},
					Key:                  "cosign.pub",
				},
				TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
					Key:                  "missing",
				},
			},
			wantErr: errMissingKey.Error(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut, mock, pulled := newSignatureTestReconciler(t, tc.sv, tc.disable)

			image := tc.image
			if image == "" {
				image = "registry/base:v1"
			}

			_, err := sut.pullBaseProfile(t.Context(), baseProfileUser(), image, logr.Discard())
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Zero(t, mock.PullCallCount())

				return
			}

			require.NoError(t, err)
			require.Equal(t, 1, mock.PullCallCount())
			require.Equal(t, tc.disable, pulled.opts.DisableSignatureVerification)
			require.Equal(t, tc.wantIdentity, pulled.opts.CertIdentity)
			require.Equal(t, tc.wantIssuer, pulled.opts.CertOidcIssuer)
			require.Equal(t, tc.wantOffline, pulled.opts.Offline)
			require.Equal(t, tc.wantKey, string(pulled.opts.KeyPEM))
			require.Equal(t, tc.wantTrustedRoot, string(pulled.opts.TrustedRootJSON))

			// The key and the trusted root are passed in memory, no file
			// is written for them.
			require.Empty(t, pulled.opts.KeyRef)
			require.Empty(t, pulled.opts.TrustedRootPath)

			if tc.wantOfficial {
				identity, issuer := pulled.opts.Signer(image)
				require.Equal(t, artifact.OfficialSignerIdentityRegexp, identity)
				require.Equal(t, artifact.OfficialSignerOidcIssuerRegexp, issuer)
			}
		})
	}
}

// An official base profile which does not verify against the trusted root of
// the SPOD is verified against the public Sigstore trusted root, like before
// the trusted root applied to official base profiles.
func TestPullOfficialBaseProfileFallsBackToPublicTrustedRoot(t *testing.T) {
	t.Parallel()

	const officialImage = "registry.k8s.io/security-profiles-operator/base/runc:v1"

	errVerify := fmt.Errorf("%w: verification failed", artifact.ErrSignatureVerification)
	sv := &spodapi.SPODSignatureVerification{
		Offline: new(true),
		TrustedRootConfigMapRef: &corev1.ConfigMapKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "sigstore"},
			Key:                  "trusted_root.json",
		},
	}

	for _, tc := range []struct {
		name      string
		image     string
		pullErrs  []error
		wantPulls int
		wantErrs  []error
	}{
		{
			name:      "official verifies with the trusted root",
			image:     officialImage,
			pullErrs:  []error{nil},
			wantPulls: 1,
		},
		{
			name:      "official falls back to the public trusted root",
			image:     officialImage,
			pullErrs:  []error{errVerify, nil},
			wantPulls: 2,
		},
		{
			name:      "official fails with both trusted roots",
			image:     officialImage,
			pullErrs:  []error{errVerify, errTest},
			wantPulls: 2,
			wantErrs:  []error{errVerify, errTest},
		},
		{
			// Only a failed verification is retried with the public
			// trusted root, not an unreachable registry.
			name:      "official does not fall back on other errors",
			image:     officialImage,
			pullErrs:  []error{errTest},
			wantPulls: 1,
			wantErrs:  []error{errTest},
		},
		{
			name:      "private does not fall back",
			image:     "registry/base:v1",
			pullErrs:  []error{errVerify},
			wantPulls: 1,
			wantErrs:  []error{errVerify},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut, mock, _ := newSignatureTestReconciler(t, sv, false)

			var pulled []artifact.PullOptions

			mock.PullStub = func(
				_ context.Context, _ logr.Logger, _, _, _ string, _ *v1.Platform, opts *artifact.PullOptions,
			) (*artifact.PullResult, error) {
				pulled = append(pulled, *opts)

				return &artifact.PullResult{}, tc.pullErrs[len(pulled)-1]
			}

			_, err := sut.pullBaseProfile(t.Context(), baseProfileUser(), tc.image, logr.Discard())
			require.Len(t, pulled, tc.wantPulls)

			if len(tc.wantErrs) > 0 {
				for _, want := range tc.wantErrs {
					require.ErrorIs(t, err, want)
				}
			} else {
				require.NoError(t, err)
			}

			require.JSONEq(t, testTrustedRoot, string(pulled[0].TrustedRootJSON))
			require.True(t, pulled[0].Offline)

			if tc.wantPulls > 1 {
				require.Empty(t, pulled[1].TrustedRootJSON)
				require.False(t, pulled[1].Offline)

				identity, issuer := pulled[1].Signer(tc.image)
				require.Equal(t, artifact.OfficialSignerIdentityRegexp, identity)
				require.Equal(t, artifact.OfficialSignerOidcIssuerRegexp, issuer)
			}
		})
	}
}
