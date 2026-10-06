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
	"context"
	"fmt"
	"time"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

// signingServiceTimeout and rekorTimeout are the timeouts cosign uses for
// the requests to Fulcio, the timestamp authorities and Rekor.
const (
	signingServiceTimeout = 30 * time.Second
	rekorTimeout          = 90 * time.Second
)

// oidcAPIVersions are the OIDC provider API versions of the signing config
// the token can be requested from.
var oidcAPIVersions = []uint32{1}

// Sign signs an artifact which is already in the registry, for example one
// whose signing failed on push. A tag gets resolved to its digest, which is
// what the signature is about.
func (a *Artifact) Sign(
	c context.Context,
	image, username, password string,
	opts *SignOptions,
) error {
	if opts == nil {
		opts = &SignOptions{}
	}

	resolveCtx, cancelResolve := context.WithTimeout(c, defaultTimeout)
	defer cancelResolve()

	ref, repo, subject, err := a.imageWithDigest(
		resolveCtx, image, username, password, opts.PlainHTTP,
	)
	if err != nil {
		return fmt.Errorf("resolving digest for image %q: %w", image, err)
	}

	a.logger.Info("Resolved image", "image", image, "reference", ref)

	session, err := a.prepareSigning(c, opts.OIDCDeviceFlow)
	if err != nil {
		return err
	}

	// The timeout starts after the sign in, which may be interactive.
	ctx, cancel := context.WithTimeout(c, defaultTimeout)
	defer cancel()

	return a.sign(ctx, repo, &subject, session)
}

// signingSession holds what signing needs from the Sigstore services and the
// identity of the signer. It is prepared before the artifact gets pushed, so
// that an interactive sign in does not count against the push timeout and a
// missing identity fails before anything gets pushed.
type signingSession struct {
	opts *sign.BundleOptions
}

// prepareSigning loads the Sigstore signing config and gets the identity
// token of the signer, interactively if the environment furnishes none.
func (a *Artifact) prepareSigning(ctx context.Context, deviceFlow bool) (*signingSession, error) {
	material, err := a.TrustedMaterial(ctx, "", false)
	if err != nil {
		// Like cosign, the trusted root only verifies the signature bundle
		// after signing, which is not required to sign.
		a.logger.Info(
			"Unable to load the Sigstore trusted root, not verifying the signature",
			"error",
			err,
		)

		material = nil
	}

	signingConfig, err := a.SigningConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load signing config: %w", err)
	}

	if signingConfig == nil {
		return nil, ErrNoSigningConfig
	}

	oidcIssuer, err := root.SelectService(
		signingConfig.OIDCProviderURLs(),
		oidcAPIVersions,
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("select OIDC provider: %w", err)
	}

	a.logger.Info("Getting the OIDC identity token for signing", "issuer", oidcIssuer.URL)

	token, err := a.IDToken(ctx, oidcIssuer.URL, deviceFlow)
	if err != nil {
		return nil, fmt.Errorf("get OIDC identity token: %w", err)
	}

	opts, err := bundleOptions(signingConfig, material, token)
	if err != nil {
		return nil, err
	}

	return &signingSession{opts: opts}, nil
}

// sign signs the artifact keylessly into a Sigstore bundle, which gets
// attached to the artifact as OCI referrer. This is the format cosign v3
// writes: an in-toto statement with the cosign signature predicate for the
// digest, signed in a DSSE envelope with a Fulcio certificate and logged in
// the transparency log of the Sigstore signing config.
func (a *Artifact) sign(
	ctx context.Context,
	repo *remote.Repository,
	subject *v1.Descriptor,
	session *signingSession,
) error {
	a.logger.Info("Signing OCI artifact", "digest", subject.Digest)

	statement, err := signatureStatement(subject.Digest)
	if err != nil {
		return err
	}

	bundle, err := a.SignBundle(
		ctx,
		&sign.DSSEData{Data: statement, PayloadType: inTotoPayloadType},
		session.opts,
	)
	if err != nil {
		return fmt.Errorf("sign artifact: %w", err)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshal signature bundle: %w", err)
	}

	if err := a.attachSignatureBundle(ctx, repo, subject, bundleJSON); err != nil {
		return fmt.Errorf("attach signature bundle: %w", err)
	}

	a.logger.Info("Signed OCI artifact", "digest", subject.Digest)

	return nil
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
		return nil, ErrRekorV2WithoutTimestampAuthority
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

// signatureStatement returns the in-toto statement cosign signs for an image
// digest.
func signatureStatement(subject digest.Digest) ([]byte, error) {
	if err := subject.Validate(); err != nil {
		return nil, fmt.Errorf("invalid digest %q: %w", subject, err)
	}

	statement, err := protojson.Marshal(&intotov1.Statement{
		Type: intotov1.StatementTypeUri,
		Subject: []*intotov1.ResourceDescriptor{{
			Digest: map[string]string{subject.Algorithm().String(): subject.Encoded()},
		}},
		PredicateType: cosignSignPredicateType,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signature statement: %w", err)
	}

	return statement, nil
}

// attachSignatureBundle attaches the signature bundle to the subject as OCI
// referrer, with the manifest layout and annotations of cosign.
func (a *Artifact) attachSignatureBundle(
	ctx context.Context, repo *remote.Repository, subject *v1.Descriptor, bundleJSON []byte,
) error {
	layer := orascontent.NewDescriptorFromBytes(bundleMediaType, bundleJSON)

	if err := a.RepositoryPush(ctx, repo, &layer, bytes.NewReader(bundleJSON)); err != nil {
		return fmt.Errorf("push bundle: %w", err)
	}

	if _, err := a.PackManifest(
		ctx,
		repo,
		oras.PackManifestVersion1_1,
		bundleMediaType,
		oras.PackManifestOptions{
			Subject: subject,
			Layers:  []v1.Descriptor{layer},
			ManifestAnnotations: map[string]string{
				v1.AnnotationCreated:          time.Now().UTC().Format(time.RFC3339),
				annotationBundleContent:       bundleContentDSSE,
				annotationBundlePredicateType: cosignSignPredicateType,
			},
		},
	); err != nil {
		return fmt.Errorf("push bundle manifest: %w", err)
	}

	return nil
}
