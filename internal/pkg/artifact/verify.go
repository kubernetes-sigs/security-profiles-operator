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
	"cmp"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2/registry/remote"
)

// verifySignature verifies the signature of the subject against the signer
// constraints of the options. Sigstore signature bundles attached as OCI
// referrers are verified if present, otherwise the legacy cosign signature
// tag, which keeps artifacts signed by older versions working. One valid
// signature is enough.
func (a *Artifact) verifySignature(
	ctx context.Context, originalImage string, repo *remote.Repository, subject *v1.Descriptor,
	signOpts *PullOptions,
) error {
	a.logger.Info("Verifying signature",
		"identityRegexp", signOpts.AllowedIdentityRegexp,
		"oidcIssuerRegexp", signOpts.AllowedOidcIssuerRegexp,
		"identity", signOpts.CertIdentity,
		"oidcIssuer", signOpts.CertOidcIssuer,
		"key", signOpts.KeyRef,
		"keyInMemory", len(signOpts.KeyPEM) > 0,
		"trustedRoot", signOpts.TrustedRootPath,
		"trustedRootInMemory", len(signOpts.TrustedRootJSON) > 0,
		"offline", signOpts.Offline,
	)

	if signOpts.hasUnconstrainedSigner() {
		a.logger.Info(
			"WARNING: signature verification is not constrained to a signer. "+
				"A signature then only proves that the artifact was signed by "+
				"somebody, not by somebody trusted. Set allowedIdentityRegexp "+
				"and allowedOidcIssuerRegexp to the signers you trust.",
			"allowedIdentityRegexp", signOpts.AllowedIdentityRegexp,
			"allowedOidcIssuerRegexp", signOpts.AllowedOidcIssuerRegexp,
			"image", originalImage,
		)
	}

	if err := a.verifySignatureOf(ctx, repo, subject, signOpts); err != nil {
		return fmt.Errorf("%w of %s: %w", ErrSignatureVerification, originalImage, err)
	}

	return nil
}

func (a *Artifact) verifySignatureOf(
	ctx context.Context, repo *remote.Repository, subject *v1.Descriptor, signOpts *PullOptions,
) error {
	if err := subject.Digest.Validate(); err != nil {
		return fmt.Errorf("invalid digest %q: %w", subject.Digest, err)
	}

	var identity *verify.CertificateIdentity

	if !signOpts.hasKey() {
		certIdentity, err := signOpts.certificateIdentity()
		if err != nil {
			return err
		}

		identity = &certIdentity
	}

	candidates, legacy, err := a.signatureCandidates(ctx, repo, subject)
	if err != nil {
		return err
	}

	if len(candidates) == 0 {
		return fmt.Errorf("%w for %s", ErrNoSignature, subject.Digest)
	}

	material, err := a.verificationMaterial(ctx, signOpts)
	if err != nil {
		return err
	}

	errs := make([]error, 0, len(candidates))

	for i := range candidates {
		candidate := &candidates[i]

		err := a.verifyCandidate(ctx, repo, candidate, legacy, subject.Digest, material, identity)
		if err == nil {
			a.logger.Info(
				"Verified signature",
				"digest",
				subject.Digest,
				"signature",
				candidate.Digest,
				"legacy",
				legacy,
			)

			return nil
		}

		errs = append(errs, fmt.Errorf("signature %s: %w", candidate.Digest, err))
	}

	return summarizeErrors(errs)
}

// verificationMaterial returns the trusted material the signatures are
// verified against: the trusted root of the options or of TUF, with the
// public key of the options if there is one.
func (a *Artifact) verificationMaterial(
	ctx context.Context, signOpts *PullOptions,
) (material root.TrustedMaterial, err error) {
	if len(signOpts.TrustedRootJSON) > 0 {
		var trustedRoot *root.TrustedRoot

		trustedRoot, err = root.NewTrustedRootFromJSON(signOpts.TrustedRootJSON)
		material = trustedRoot
	} else {
		material, err = a.TrustedMaterial(ctx, signOpts.TrustedRootPath, signOpts.Offline)
	}

	if err != nil {
		return nil, fmt.Errorf("load trusted root: %w", err)
	}

	if material == nil {
		return nil, ErrNoTrustedRoot
	}

	switch {
	case len(signOpts.KeyPEM) > 0:
		return withPublicKeyPEM(material, signOpts.KeyPEM)
	case signOpts.KeyRef != "":
		return a.withPublicKey(material, signOpts.KeyRef)
	default:
		return material, nil
	}
}

// summarizeErrors joins the first maxReportedSignatureErrors errors and
// counts the others, so that an artifact with many invalid signatures does not
// produce an error message of arbitrary length.
func summarizeErrors(errs []error) error {
	if len(errs) <= maxReportedSignatureErrors {
		return errors.Join(errs...)
	}

	return errors.Join(
		errors.Join(errs[:maxReportedSignatureErrors]...),
		fmt.Errorf(
			"%d more signatures failed to verify", len(errs)-maxReportedSignatureErrors,
		),
	)
}

// signatureCandidates returns the referrer manifests of the signature
// bundles of the subject, or the layers of its legacy signature tag if there
// are no bundles. Attestations like SLSA provenance or promotion records are
// bundles with other predicate types, which do not count as signature. A
// failed lookup of the bundles is part of the error if no legacy signature
// is found either.
func (a *Artifact) signatureCandidates(
	ctx context.Context, repo *remote.Repository, subject *v1.Descriptor,
) (candidates []v1.Descriptor, legacy bool, err error) {
	referrers, referrersErr := a.SignatureReferrers(ctx, repo, subject)
	if referrersErr != nil {
		a.logger.Info(
			"Unable to look up signature bundles, verifying legacy signatures",
			"error",
			referrersErr,
		)
	}

	for i := range referrers {
		if isSignatureReferrer(&referrers[i]) {
			candidates = append(candidates, referrers[i])
		}
	}

	if len(candidates) > 0 {
		return candidates[:min(len(candidates), maxSignatures)], false, nil
	}

	candidates, err = a.legacySignatureLayers(ctx, repo, subject.Digest)

	switch {
	case err != nil && referrersErr != nil:
		return nil, true, fmt.Errorf(
			"%w, looking up signature bundles failed as well: %w", err, referrersErr,
		)
	case err != nil:
		return nil, true, err
	case len(candidates) == 0 && referrersErr != nil:
		return nil, true, fmt.Errorf(
			"%w for %s, looking up signature bundles failed: %w",
			ErrNoSignature, subject.Digest, referrersErr,
		)
	}

	return candidates, true, nil
}

// isSignatureReferrer reports whether the referrer is a signature bundle, as
// opposed to an attestation or any other artifact referring to the subject.
func isSignatureReferrer(referrer *v1.Descriptor) bool {
	return referrer.Annotations[annotationBundlePredicateType] == cosignSignPredicateType
}

// verifyCandidate fetches and verifies one signature.
func (a *Artifact) verifyCandidate(
	ctx context.Context,
	repo *remote.Repository,
	candidate *v1.Descriptor,
	legacy bool,
	subject digest.Digest,
	material root.TrustedMaterial,
	identity *verify.CertificateIdentity,
) error {
	var (
		bundle   *sgbundle.Bundle
		artifact verify.ArtifactPolicyOption
	)

	if legacy {
		signedPayload, err := a.fetchLimited(ctx, repo, candidate, maxSignatureSize)
		if err != nil {
			return fmt.Errorf("fetch payload: %w", err)
		}

		if err := checkLegacyClaims(signedPayload, subject); err != nil {
			return err
		}

		bundle, err = legacyBundle(candidate.Annotations, signedPayload)
		if err != nil {
			return err
		}

		artifact = verify.WithArtifact(bytes.NewReader(signedPayload))
	} else {
		var err error

		bundle, err = a.fetchSignatureBundle(ctx, repo, candidate)
		if err != nil {
			return err
		}

		if err := checkStatement(bundle); err != nil {
			return err
		}

		digestBytes, err := hex.DecodeString(subject.Encoded())
		if err != nil {
			return fmt.Errorf("decode digest: %w", err)
		}

		// The digest has to be a subject of the signed statement.
		artifact = verify.WithArtifactDigest(subject.Algorithm().String(), digestBytes)
	}

	config, err := newVerifierConfig(bundle, material, identity == nil)
	if err != nil {
		return err
	}

	return a.VerifyEntity(bundle, material, config.options(), artifact, identity)
}

// fetchSignatureBundle fetches the Sigstore bundle of a referrer manifest,
// which cosign writes as its only layer.
func (a *Artifact) fetchSignatureBundle(
	ctx context.Context, repo *remote.Repository, referrer *v1.Descriptor,
) (*sgbundle.Bundle, error) {
	raw, err := a.fetchLimited(ctx, repo, referrer, maxSignatureManifestSize)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle manifest: %w", err)
	}

	var manifest v1.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode bundle manifest: %w", err)
	}

	if len(manifest.Layers) != 1 ||
		!strings.HasPrefix(manifest.Layers[0].MediaType, bundleMediaTypePrefix) {
		return nil, ErrInvalidSignatureBundle
	}

	raw, err = a.fetchLimited(ctx, repo, &manifest.Layers[0], maxSignatureSize)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}

	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}

	bundle, err := sgbundle.NewBundle(&pb)
	if err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	if !bundle.MinVersion("v0.3") {
		return nil, fmt.Errorf("%w: version older than v0.3", ErrInvalidSignatureBundle)
	}

	return bundle, nil
}

// fetchLimited fetches the content of the descriptor unless it is larger than
// limit.
func (a *Artifact) fetchLimited(
	ctx context.Context, repo *remote.Repository, desc *v1.Descriptor, limit int64,
) ([]byte, error) {
	if err := blobSizeLimit(limit)(ctx, *desc); err != nil {
		return nil, err
	}

	return a.FetchAll(ctx, repo, desc)
}

// checkStatement ensures that the bundle signs an in-toto statement with the
// cosign signature predicate. Its subject is checked by the verification.
func checkStatement(bundle *sgbundle.Bundle) error {
	envelope, err := bundle.Envelope()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignatureBundle, err)
	}

	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignatureBundle, err)
	}

	if statement.GetPredicateType() != cosignSignPredicateType {
		return fmt.Errorf(
			"%w: predicate type %q",
			ErrInvalidSignatureBundle,
			statement.GetPredicateType(),
		)
	}

	return nil
}

// verifierConfig are the verification requirements for a signature, which
// match the defaults of cosign verify.
type verifierConfig struct {
	// keyed verifies with a public key instead of a certificate, which does
	// not need a timestamp.
	keyed bool

	// signedCertificateTimestamps requires the certificate to be logged in a
	// certificate transparency log of the trusted root.
	signedCertificateTimestamps bool

	// signedTimestamps uses the timestamps of timestamp authorities instead
	// of the time the transparency log integrated the entry, for Rekor v2
	// entries, which carry no such time.
	signedTimestamps bool
}

func newVerifierConfig(
	entity verify.SignedEntity, material root.TrustedMaterial, keyed bool,
) (verifierConfig, error) {
	config := verifierConfig{
		keyed: keyed,
		// A trusted root without certificate transparency logs, like the one
		// of a private Sigstore deployment without one, cannot verify any
		// certificate timestamp.
		signedCertificateTimestamps: !keyed && len(material.CTLogs()) > 0,
	}

	if keyed {
		return config, nil
	}

	entries, err := entity.TlogEntries()
	if err != nil {
		return verifierConfig{}, fmt.Errorf("%w: %w", ErrInvalidSignatureBundle, err)
	}

	rekorV1, rekorV2 := false, false

	for _, entry := range entries {
		if entry.IntegratedTime().IsZero() {
			rekorV2 = true
		} else {
			rekorV1 = true
		}
	}

	config.signedTimestamps = rekorV2 && !rekorV1

	return config, nil
}

func (c verifierConfig) options() []verify.VerifierOption {
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1)}

	if c.signedCertificateTimestamps {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}

	switch {
	case c.keyed:
		opts = append(opts, verify.WithNoObserverTimestamps())
	case c.signedTimestamps:
		opts = append(opts, verify.WithSignedTimestamps(1))
	default:
		opts = append(opts, verify.WithIntegratedTimestamps(1))
	}

	return opts
}

// certificateIdentity returns the identity the keyless signature certificate
// has to match. An exact identity or issuer replaces the regexp, an empty
// regexp matches everything.
func (p *PullOptions) certificateIdentity() (verify.CertificateIdentity, error) {
	identityRegexp := cmp.Or(p.AllowedIdentityRegexp, allowAllRegexp)
	if p.CertIdentity != "" {
		identityRegexp = ""
	}

	issuerRegexp := cmp.Or(p.AllowedOidcIssuerRegexp, allowAllRegexp)
	if p.CertOidcIssuer != "" {
		issuerRegexp = ""
	}

	san, err := verify.NewSANMatcher(p.CertIdentity, identityRegexp)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("invalid identity regexp: %w", err)
	}

	issuer, err := verify.NewIssuerMatcher(p.CertOidcIssuer, issuerRegexp)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("invalid OIDC issuer regexp: %w", err)
	}

	return verify.NewCertificateIdentity(san, issuer, certificate.Extensions{})
}

// withPublicKey returns the trusted material with the public key of the
// PEM file as the key signatures are verified with.
func (a *Artifact) withPublicKey(
	material root.TrustedMaterial,
	keyRef string,
) (root.TrustedMaterial, error) {
	if strings.Contains(keyRef, "://") {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyRef, keyRef)
	}

	raw, err := a.ReadFile(keyRef)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	return withPublicKeyPEM(material, raw)
}

// withPublicKeyPEM returns the trusted material with the PEM encoded public
// key as the key signatures are verified with.
func withPublicKeyPEM(
	material root.TrustedMaterial,
	raw []byte,
) (root.TrustedMaterial, error) {
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("load public key: %w", err)
	}

	return &keyTrustedMaterial{
		TrustedMaterial: material,
		key:             root.NewExpiringKey(verifier, time.Time{}, time.Time{}),
	}, nil
}

// keyTrustedMaterial is trusted material which verifies key signatures with
// a fixed public key, no matter which key hint they carry.
type keyTrustedMaterial struct {
	root.TrustedMaterial

	key root.TimeConstrainedVerifier
}

func (k *keyTrustedMaterial) PublicKeyVerifier(string) (root.TimeConstrainedVerifier, error) {
	return k.key, nil
}
