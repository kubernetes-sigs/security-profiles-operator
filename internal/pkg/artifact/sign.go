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
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
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

	// Without a signer, nothing has to be looked up first.
	if err := a.CheckKeylessSigner(); err != nil {
		return err
	}

	resolveCtx, cancelResolve := context.WithTimeout(c, DefaultTimeout)
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
	ctx, cancel := context.WithTimeout(c, DefaultTimeout)
	defer cancel()

	return a.sign(ctx, repo, &subject, session)
}

// signingSession holds what signing needs from the Sigstore services and the
// identity of the signer. It is prepared before the artifact gets pushed, so
// that an interactive sign in does not count against the push timeout and a
// missing identity fails before anything gets pushed.
type signingSession struct {
	signDSSE func(context.Context, []byte, string) (*protobundle.Bundle, error)
}

// prepareSigning loads the Sigstore signing config and gets the identity
// token of the signer, interactively if the environment furnishes none. The
// TUF requests and the lookups in the environment have their own timeouts,
// the interactive sign in has none.
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

	// The identity token comes from the environment, like in CI, or from a
	// sign in at an OIDC provider of the signing config. A signing config
	// without OIDC providers, like the one of a private Sigstore deployment
	// whose Fulcio trusts the CI issuer directly, still signs with a token
	// of the environment.
	issuer := ""

	oidcIssuer, err := root.SelectService(
		signingConfig.OIDCProviderURLs(),
		oidcAPIVersions,
		time.Now(),
	)
	if err == nil {
		issuer = oidcIssuer.URL
	} else {
		a.logger.Info(
			"No OIDC provider in the signing config, using an identity token of the environment",
			"error", err.Error(),
		)
	}

	a.logger.Info("Getting the OIDC identity token for signing", "issuer", issuer)

	token, err := a.IDToken(ctx, issuer, deviceFlow)
	if err != nil {
		return nil, fmt.Errorf("get OIDC identity token: %w", err)
	}

	signDSSE, err := a.DSSESigner(signingConfig, material, token)
	if err != nil {
		return nil, err
	}

	return &signingSession{signDSSE: signDSSE}, nil
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

	bundle, err := session.signDSSE(ctx, statement, inTotoPayloadType)
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
