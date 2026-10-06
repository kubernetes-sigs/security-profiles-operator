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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact/artifactfakes"
)

// pushSigningMock returns a fake which pushes and signs successfully.
func pushSigningMock(t *testing.T) *artifactfakes.FakeImpl {
	t.Helper()

	testRef, err := name.ParseReference("registry.example.com/foo/bar:v1")
	require.NoError(t, err)

	mock := &artifactfakes.FakeImpl{}
	stubSigning(t, mock)
	mock.StoreAddReturns(defaultDescriptor(), nil)
	mock.ParseReferenceReturns(testRef, nil)
	mock.NewRepositoryReturns(&remote.Repository{
		Reference: registry.Reference{Registry: "registry.example.com", Repository: "foo/bar"},
	}, nil)

	return mock
}

func push(t *testing.T, ctx context.Context, mock *artifactfakes.FakeImpl) error {
	t.Helper()

	sut := New(logr.Discard())
	sut.impl = mock

	return sut.Push(
		ctx,
		map[*ocispec.Platform]string{nil: "profile.yaml"},
		"registry.example.com/foo/bar:v1",
		"",
		"",
		nil,
		nil,
	)
}

// TestPushSignsInBeforeTheTimeout verifies that the identity token is
// requested before the push timeout starts, and that a missing identity
// fails the push before anything gets pushed.
func TestPushSignsInBeforeTheTimeout(t *testing.T) {
	t.Parallel()

	mock := pushSigningMock(t)
	mock.IDTokenStub = func(ctx context.Context, _ string, _ bool) (string, error) {
		_, hasDeadline := ctx.Deadline()
		require.False(t, hasDeadline, "the sign in must not count against the push timeout")

		return "token", nil
	}
	mock.CopyStub = func(
		ctx context.Context, _ oras.ReadOnlyTarget, _ string, _ oras.Target, _ string, _ oras.CopyOptions,
	) (ocispec.Descriptor, error) {
		_, hasDeadline := ctx.Deadline()
		require.True(t, hasDeadline, "the push has a timeout")

		return testSubject(), nil
	}

	require.NoError(t, push(t, context.Background(), mock))
	require.Equal(t, 1, mock.IDTokenCallCount())
	require.Equal(t, 1, mock.CopyCallCount())
	require.Equal(t, 1, mock.SignBundleCallCount())

	mock = pushSigningMock(t)
	mock.IDTokenReturns("", ErrNoInteractiveSignIn)

	require.ErrorIs(t, push(t, t.Context(), mock), ErrNoInteractiveSignIn)
	require.Zero(t, mock.CopyCallCount())
}

// TestPushUnsigned verifies that a failed signature after the push names the
// pushed digest, so that it can be signed afterwards.
func TestPushUnsigned(t *testing.T) {
	t.Parallel()

	mock := pushSigningMock(t)
	mock.SignBundleReturns(nil, errTest)

	err := push(t, t.Context(), mock)
	require.ErrorIs(t, err, errTest)

	var unsigned *UnsignedError
	require.ErrorAs(t, err, &unsigned)
	require.Equal(
		t, "registry.example.com/foo/bar@"+testSubject().Digest.String(), unsigned.Reference,
	)
	require.ErrorContains(t, err, "pushed "+unsigned.Reference+", but signing it failed")
}

// TestSign signs an artifact which got pushed without signature and verifies
// it on pull, with the trusted root and the public key passed in memory.
func TestSign(t *testing.T) {
	t.Parallel()

	host := testRegistry(t, true)
	sigstore := newTestSigstore(t)

	sut := New(logr.Discard())
	subject := pushUnsigned(t, sut, host, "unsigned")

	trustedRootJSON, err := os.ReadFile(sigstore.trustedRootPath)
	require.NoError(t, err)

	pull := func(opts PullOptions) error {
		opts.PlainHTTP = true
		opts.TrustedRootJSON = trustedRootJSON

		_, err := sut.Pull(t.Context(), host+"/unsigned:v1", "", "", nil, &opts)

		return err
	}

	require.ErrorIs(t, pull(PullOptions{}), ErrNoSignature)

	sut.impl = &testSigstoreImpl{t: t, sigstore: sigstore, identity: testIdentity}
	require.NoError(t, sut.Sign(
		t.Context(), host+"/unsigned:v1", "", "", &SignOptions{PlainHTTP: true},
	))

	signatures, err := signatureReferrers(
		t.Context(), testRepository(t, host, "unsigned"), &subject, maxSignatures, maxReferrers,
	)
	require.NoError(t, err)
	require.Len(t, signatures, 1)

	require.NoError(t, pull(PullOptions{CertIdentity: testIdentity, CertOidcIssuer: testIssuer}))
	require.ErrorContains(
		t,
		pull(PullOptions{CertIdentity: "other@example.com"}),
		"verify signature",
	)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	otherKeyPEM, err := os.ReadFile(writePublicKey(t, otherKey.Public()))
	require.NoError(t, err)

	require.ErrorContains(t, pull(PullOptions{KeyPEM: otherKeyPEM}), "verify signature")
}

func TestSignUnknownImage(t *testing.T) {
	t.Parallel()

	host := testRegistry(t, true)

	sut := New(logr.Discard())
	sut.impl = &testSigstoreImpl{t: t, sigstore: newTestSigstore(t), identity: testIdentity}

	err := sut.Sign(t.Context(), host+"/missing:v1", "", "", &SignOptions{PlainHTTP: true})
	require.ErrorContains(t, err, "resolving digest for image")
}
