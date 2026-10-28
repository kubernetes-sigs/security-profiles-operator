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

package dsse

import (
	"context"
	"errors"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/stretchr/testify/require"
)

type contextKey struct{}

var errTest = errors.New("test")

// fakeCertificateProvider returns the certificate and records the context
// and the identity token it got.
type fakeCertificateProvider struct {
	certificate []byte
	err         error
	ctx         context.Context //nolint:containedctx // recorded for the assertions
	token       string
}

func (f *fakeCertificateProvider) GetCertificate(
	ctx context.Context, _ sign.Keypair, opts *sign.CertificateProviderOptions,
) ([]byte, error) {
	f.ctx = ctx
	f.token = opts.IDToken

	return f.certificate, f.err
}

// fakeTransparency records the context, the verifier and the bundle it got.
type fakeTransparency struct {
	ctx      context.Context //nolint:containedctx // recorded for the assertions
	verifier []byte
	bundle   *protobundle.Bundle
}

func (f *fakeTransparency) GetTransparencyLogEntry(
	ctx context.Context, verifier []byte, bundle *protobundle.Bundle,
) error {
	f.ctx = ctx
	f.verifier = verifier
	f.bundle = bundle

	return nil
}

func TestSign(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), contextKey{}, "value")
	provider := &fakeCertificateProvider{certificate: []byte("certificate")}
	transparency := &fakeTransparency{}

	bundle, err := Sign(ctx, &sign.BundleOptions{
		CertificateProvider:        provider,
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: "token"},
		TransparencyLogs:           []sign.Transparency{transparency},
	}, []byte("payload"), "application/vnd.in-toto+json")
	require.NoError(t, err)

	envelope := bundle.GetDsseEnvelope()
	require.NotNil(t, envelope)
	require.Equal(t, "application/vnd.in-toto+json", envelope.GetPayloadType())
	require.Equal(t, []byte("payload"), envelope.GetPayload())
	require.Len(t, envelope.GetSignatures(), 1)
	require.Equal(
		t, []byte("certificate"), bundle.GetVerificationMaterial().GetCertificate().GetRawBytes(),
	)

	// The requests to the services get the context of the caller.
	require.Equal(t, "value", provider.ctx.Value(contextKey{}))
	require.Equal(t, "token", provider.token)
	require.Equal(t, "value", transparency.ctx.Value(contextKey{}))
	require.Contains(t, string(transparency.verifier), "BEGIN CERTIFICATE")
	require.Same(t, bundle, transparency.bundle)
}

func TestSignCertificateFailure(t *testing.T) {
	t.Parallel()

	_, err := Sign(t.Context(), &sign.BundleOptions{
		CertificateProvider:        &fakeCertificateProvider{err: errTest},
		CertificateProviderOptions: &sign.CertificateProviderOptions{},
	}, []byte("payload"), "application/vnd.in-toto+json")
	require.ErrorIs(t, err, errTest)
}
