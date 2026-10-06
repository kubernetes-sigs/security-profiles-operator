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
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact/artifactfakes"
)

// signatureCandidatesMock returns a fake with count signature bundle
// referrers, which all hold the same valid bundle.
func signatureCandidatesMock(t *testing.T, count int) *artifactfakes.FakeImpl {
	t.Helper()

	mock := &artifactfakes.FakeImpl{}
	stubSignature(mock)

	referrers, err := mock.SignatureReferrers(t.Context(), nil, nil)
	require.NoError(t, err)
	require.Len(t, referrers, 1)

	candidates := make([]ocispec.Descriptor, count)
	for i := range candidates {
		candidates[i] = referrers[0]
	}

	mock.SignatureReferrersReturns(candidates, nil)

	return mock
}

func TestVerifySignatureOfStopsAtFirstValid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		failFirst int
		wantCalls int
	}{
		{name: "first valid", wantCalls: 1},
		{name: "third valid", failFirst: 2, wantCalls: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := signatureCandidatesMock(t, 5)
			for i := range tc.failFirst {
				mock.VerifyEntityReturnsOnCall(i, errTest)
			}

			sut := New(logr.Discard())
			sut.impl = mock

			subject := testSubject()
			require.NoError(t, sut.verifySignatureOf(
				t.Context(), &remote.Repository{}, &subject, &PullOptions{},
			))
			require.Equal(t, tc.wantCalls, mock.VerifyEntityCallCount())
		})
	}
}

func TestVerifySignatureOfSummarizesErrors(t *testing.T) {
	t.Parallel()

	mock := signatureCandidatesMock(t, maxSignatures)
	mock.VerifyEntityReturns(errTest)

	sut := New(logr.Discard())
	sut.impl = mock

	subject := testSubject()
	err := sut.verifySignatureOf(t.Context(), &remote.Repository{}, &subject, &PullOptions{})
	require.ErrorIs(t, err, errTest)
	require.ErrorContains(
		t, err,
		strconv.Itoa(maxSignatures-maxReportedSignatureErrors)+" more signatures failed to verify",
	)
	require.Equal(t, maxSignatures, mock.VerifyEntityCallCount())
}

func TestSummarizeErrors(t *testing.T) {
	t.Parallel()

	require.Equal(t, 3, maxReportedSignatureErrors)

	errs := make([]error, 5)
	for i := range errs {
		errs[i] = fmt.Errorf("error %d", i)
	}

	require.NoError(t, summarizeErrors(nil))

	err := summarizeErrors(errs[:3])
	require.Equal(t, "error 0\nerror 1\nerror 2", err.Error())

	err = summarizeErrors(errs)
	require.ErrorIs(t, err, errs[0])
	require.ErrorIs(t, err, errs[2])
	require.NotErrorIs(t, err, errs[3])
	require.Equal(t, "error 0\nerror 1\nerror 2\n2 more signatures failed to verify", err.Error())
}

func TestSignatureCandidatesKeepsReferrersError(t *testing.T) {
	t.Parallel()

	errLegacy := errors.New("legacy")

	for _, tc := range []struct {
		name      string
		legacyErr error
		wantErrs  []error
	}{
		{
			name:      "no legacy signature",
			legacyErr: errdef.ErrNotFound,
			wantErrs:  []error{ErrNoSignature, errTest},
		},
		{
			name:      "legacy lookup fails",
			legacyErr: errLegacy,
			wantErrs:  []error{errLegacy, errTest},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &artifactfakes.FakeImpl{}
			mock.SignatureReferrersReturns(nil, errTest)
			mock.FetchReferenceReturns(ocispec.Descriptor{}, nil, tc.legacyErr)

			sut := New(logr.Discard())
			sut.impl = mock

			subject := testSubject()
			_, _, err := sut.signatureCandidates(t.Context(), &remote.Repository{}, &subject)

			for _, want := range tc.wantErrs {
				require.ErrorIs(t, err, want)
			}
		})
	}
}

func TestPullNamesTheImageOnVerificationFailure(t *testing.T) {
	t.Parallel()

	const image = "registry.example.com/profiles/runc:v1"

	ref, err := name.ParseReference(image)
	require.NoError(t, err)

	mock := &artifactfakes.FakeImpl{}
	stubProfile(mock, "")
	mock.ParseReferenceReturns(ref, nil)
	mock.NewRepositoryReturns(&remote.Repository{}, nil)
	mock.ResolveRepositoryReturns(testSubject(), nil)
	mock.VerifyEntityReturns(errTest)

	sut := New(logr.Discard())
	sut.impl = mock

	_, err = sut.Pull(t.Context(), image, "", "", nil, &PullOptions{})
	require.ErrorIs(t, err, errTest)
	require.ErrorIs(t, err, ErrSignatureVerification)
	require.ErrorContains(t, err, "verify signature of "+image)
}

func TestVerificationMaterial(t *testing.T) {
	t.Parallel()

	sigstore := newTestSigstore(t)

	trustedRootJSON, err := os.ReadFile(sigstore.trustedRootPath)
	require.NoError(t, err)

	keyPath := writePublicKey(t, sigstore.fulcioKey.Public())

	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	for _, tc := range []struct {
		name                string
		opts                PullOptions
		wantErr             string
		wantKey             bool
		wantTrustedMaterial int
		wantReadFile        int
	}{
		{
			name:                "trusted root of TUF",
			wantTrustedMaterial: 1,
		},
		{
			name: "trusted root JSON takes precedence over the path",
			opts: PullOptions{
				TrustedRootJSON: trustedRootJSON,
				TrustedRootPath: "/does/not/exist",
			},
		},
		{
			name:    "invalid trusted root JSON",
			opts:    PullOptions{TrustedRootJSON: []byte("not JSON")},
			wantErr: "load trusted root",
		},
		{
			name:         "key file",
			opts:         PullOptions{KeyRef: keyPath},
			wantKey:      true,
			wantReadFile: 1,

			wantTrustedMaterial: 1,
		},
		{
			name:                "key PEM takes precedence over the file",
			opts:                PullOptions{KeyPEM: keyPEM, KeyRef: "/does/not/exist"},
			wantKey:             true,
			wantTrustedMaterial: 1,
		},
		{
			name:                "invalid key PEM",
			opts:                PullOptions{KeyPEM: []byte("not a key")},
			wantErr:             "decode public key",
			wantTrustedMaterial: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &artifactfakes.FakeImpl{}
			mock.TrustedMaterialReturns(&root.BaseTrustedMaterial{}, nil)
			mock.ReadFileReturns(keyPEM, nil)

			sut := New(logr.Discard())
			sut.impl = mock

			material, err := sut.verificationMaterial(t.Context(), &tc.opts)
			require.Equal(t, tc.wantTrustedMaterial, mock.TrustedMaterialCallCount())
			require.Equal(t, tc.wantReadFile, mock.ReadFileCallCount())

			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)

			_, isKey := material.(*keyTrustedMaterial)
			require.Equal(t, tc.wantKey, isKey)
		})
	}
}
