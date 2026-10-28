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

// Package signing has the Sigstore clients which sign artifacts keylessly.
// It is a package of its own, so that the operator, which only pulls
// artifacts, does not link them.
package signing

import (
	"context"
	"fmt"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact/signing/dsse"
)

// signingServiceTimeout and rekorTimeout are the timeouts cosign uses for
// the requests to Fulcio, the timestamp authorities and Rekor.
const (
	signingServiceTimeout = 30 * time.Second
	rekorTimeout          = 90 * time.Second
)

// Signer is the artifact.KeylessSigner of Sigstore.
type Signer struct{}

// New returns a new Signer.
func New() *Signer {
	return &Signer{}
}

var _ artifact.KeylessSigner = &Signer{}

// IDToken returns an identity token for Fulcio, see idToken.
func (*Signer) IDToken(ctx context.Context, issuer string, deviceFlow bool) (string, error) {
	return idToken(ctx, issuer, deviceFlow)
}

// DSSESigner selects the Fulcio instance, the timestamp authorities and the
// transparency logs of the signing config, the way cosign does. The returned
// function signs with an ephemeral key and a Fulcio certificate for the
// identity token into a Sigstore bundle.
func (*Signer) DSSESigner(
	signingConfig *root.SigningConfig, material root.TrustedMaterial, token string,
) (func(context.Context, []byte, string) (*protobundle.Bundle, error), error) {
	opts, err := bundleOptions(signingConfig, material, token)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, payload []byte, payloadType string) (*protobundle.Bundle, error) {
		return dsse.Sign(ctx, opts, payload, payloadType)
	}, nil
}

// bundleOptions selects the Fulcio instance, the timestamp authorities and
// the transparency logs of the signing config, the way cosign does.
func bundleOptions(
	signingConfig *root.SigningConfig, material root.TrustedMaterial, token string,
) (*sign.BundleOptions, error) {
	now := time.Now()

	fulcio, err := root.SelectService(
		signingConfig.FulcioCertificateAuthorityURLs(),
		sign.FulcioAPIVersions,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("select Fulcio instance: %w", err)
	}

	opts := &sign.BundleOptions{
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcio.URL,
			Timeout: signingServiceTimeout,
			Retries: 1,
		}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: token},
		TrustedRoot:                material,
	}

	opts.TimestampAuthorities, err = timestampAuthorities(signingConfig, now)
	if err != nil {
		return nil, err
	}

	var rekorV2 bool

	opts.TransparencyLogs, rekorV2, err = transparencyLogs(signingConfig, now)
	if err != nil {
		return nil, err
	}

	// Rekor v2 does not timestamp its entries, so the short lived Fulcio
	// certificate needs a timestamp authority to be verifiable.
	if rekorV2 && len(opts.TimestampAuthorities) == 0 {
		return nil, artifact.ErrRekorV2WithoutTimestampAuthority
	}

	return opts, nil
}

// timestampAuthorities returns the timestamp authorities of the signing
// config to use.
func timestampAuthorities(
	signingConfig *root.SigningConfig, now time.Time,
) ([]*sign.TimestampAuthority, error) {
	if len(signingConfig.TimestampAuthorityURLs()) == 0 {
		return nil, nil
	}

	authorities, err := root.SelectServices(
		signingConfig.TimestampAuthorityURLs(), signingConfig.TimestampAuthorityURLsConfig(),
		sign.TimestampAuthorityAPIVersions, now,
	)
	if err != nil {
		return nil, fmt.Errorf("select timestamp authorities: %w", err)
	}

	result := make([]*sign.TimestampAuthority, 0, len(authorities))

	for _, authority := range authorities {
		result = append(result, sign.NewTimestampAuthority(
			&sign.TimestampAuthorityOptions{
				URL:     authority.URL,
				Timeout: signingServiceTimeout,
				Retries: 1,
			},
		))
	}

	return result, nil
}

// transparencyLogs returns the transparency logs of the signing config to
// use, and whether one of them is a Rekor v2 log.
func transparencyLogs(
	signingConfig *root.SigningConfig, now time.Time,
) (result []sign.Transparency, rekorV2 bool, err error) {
	if len(signingConfig.RekorLogURLs()) == 0 {
		return nil, false, nil
	}

	logs, err := root.SelectServices(
		signingConfig.RekorLogURLs(),
		signingConfig.RekorLogURLsConfig(),
		sign.RekorAPIVersions,
		now,
	)
	if err != nil {
		return nil, false, fmt.Errorf("select transparency logs: %w", err)
	}

	result = make([]sign.Transparency, 0, len(logs))

	for _, log := range logs {
		rekorV2 = rekorV2 || log.MajorAPIVersion == 2
		result = append(result, sign.NewRekor(&sign.RekorOptions{
			BaseURL: log.URL,
			Timeout: rekorTimeout,
			Retries: 1,
			Version: log.MajorAPIVersion,
		}))
	}

	return result, rekorV2, nil
}
