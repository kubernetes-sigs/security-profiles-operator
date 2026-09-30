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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"
	orascontent "oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
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

// sign signs the pushed artifact keylessly into a Sigstore bundle, which gets
// attached to the artifact as OCI referrer. This is the format cosign v3
// writes: an in-toto statement with the cosign signature predicate for the
// digest, signed in a DSSE envelope with a Fulcio certificate and logged in
// the transparency log of the Sigstore signing config.
func (a *Artifact) sign(
	ctx context.Context,
	repo *remote.Repository,
	subject *v1.Descriptor,
) error {
	a.logger.Info("Signing OCI artifact", "digest", subject.Digest)

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
		return fmt.Errorf("load signing config: %w", err)
	}

	if signingConfig == nil {
		return ErrNoSigningConfig
	}

	oidcIssuer, err := root.SelectService(
		signingConfig.OIDCProviderURLs(),
		oidcAPIVersions,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("select OIDC provider: %w", err)
	}

	token, err := a.IDToken(ctx, oidcIssuer.URL)
	if err != nil {
		return fmt.Errorf("get OIDC identity token: %w", err)
	}

	opts, err := bundleOptions(signingConfig, material, token)
	if err != nil {
		return err
	}

	statement, err := signatureStatement(subject.Digest)
	if err != nil {
		return err
	}

	bundle, err := a.SignBundle(
		ctx,
		&sign.DSSEData{Data: statement, PayloadType: inTotoPayloadType},
		opts,
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

	if len(signingConfig.TimestampAuthorityURLs()) > 0 {
		authorities, err := root.SelectServices(
			signingConfig.TimestampAuthorityURLs(), signingConfig.TimestampAuthorityURLsConfig(),
			sign.TimestampAuthorityAPIVersions, now,
		)
		if err != nil {
			return nil, fmt.Errorf("select timestamp authorities: %w", err)
		}

		for _, authority := range authorities {
			opts.TimestampAuthorities = append(
				opts.TimestampAuthorities,
				sign.NewTimestampAuthority(
					&sign.TimestampAuthorityOptions{
						URL:     authority.URL,
						Timeout: signingServiceTimeout,
						Retries: 1,
					},
				),
			)
		}
	}

	rekorV2 := false

	if len(signingConfig.RekorLogURLs()) > 0 {
		logs, err := root.SelectServices(
			signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(),
			sign.RekorAPIVersions,
			now,
		)
		if err != nil {
			return nil, fmt.Errorf("select transparency logs: %w", err)
		}

		for _, log := range logs {
			rekorV2 = rekorV2 || log.MajorAPIVersion == 2
			opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{
				BaseURL: log.URL,
				Timeout: rekorTimeout,
				Retries: 1,
				Version: log.MajorAPIVersion,
			}))
		}
	}

	// Rekor v2 does not timestamp its entries, so the short lived Fulcio
	// certificate needs a timestamp authority to be verifiable.
	if rekorV2 && len(opts.TimestampAuthorities) == 0 {
		return nil, ErrRekorV2WithoutTimestampAuthority
	}

	return opts, nil
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
		"trustedRoot", signOpts.TrustedRootPath,
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
		return fmt.Errorf("verify signature: %w", err)
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

	if signOpts.KeyRef == "" {
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

	material, err := a.TrustedMaterial(ctx, signOpts.TrustedRootPath, signOpts.Offline)
	if err != nil {
		return fmt.Errorf("load trusted root: %w", err)
	}

	if material == nil {
		return ErrNoTrustedRoot
	}

	if signOpts.KeyRef != "" {
		material, err = a.withPublicKey(material, signOpts.KeyRef)
		if err != nil {
			return err
		}
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

	return errors.Join(errs...)
}

// signatureCandidates returns the referrer manifests of the signature
// bundles of the subject, or the layers of its legacy signature tag if there
// are no bundles. Attestations like SLSA provenance or promotion records are
// bundles with other predicate types, which do not count as signature.
func (a *Artifact) signatureCandidates(
	ctx context.Context, repo *remote.Repository, subject *v1.Descriptor,
) (candidates []v1.Descriptor, legacy bool, err error) {
	referrers, err := a.Referrers(ctx, repo, subject)
	if err != nil {
		a.logger.Info(
			"Unable to look up signature bundles, verifying legacy signatures",
			"error",
			err,
		)
	}

	for i := range referrers {
		if referrers[i].Annotations[annotationBundlePredicateType] == cosignSignPredicateType {
			candidates = append(candidates, referrers[i])
		}
	}

	if len(candidates) > 0 {
		return candidates[:min(len(candidates), maxSignatures)], false, nil
	}

	candidates, err = a.legacySignatureLayers(ctx, repo, subject.Digest)
	if err != nil {
		return nil, true, err
	}

	return candidates, true, nil
}

// legacySignatureLayers returns the layers of the signature tag cosign v2 and
// older versions of this project attach to the digest, every layer being one
// signature.
func (a *Artifact) legacySignatureLayers(
	ctx context.Context, repo *remote.Repository, subject digest.Digest,
) ([]v1.Descriptor, error) {
	tag := fmt.Sprintf("%s-%s%s", subject.Algorithm(), subject.Encoded(), legacySignatureTagSuffix)

	// The manifest is fetched by tag like cosign does. registry.k8s.io
	// serves the signature tags from the backend which holds them, but
	// redirects digests to the closest mirror, which may not.
	_, raw, err := a.FetchReference(ctx, repo, tag, maxSignatureManifestSize)
	if errors.Is(err, errdef.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("fetch signature tag %s: %w", tag, err)
	}

	var manifest v1.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode signature tag %s: %w", tag, err)
	}

	return manifest.Layers[:min(len(manifest.Layers), maxSignatures)], nil
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

// checkLegacyClaims ensures that a legacy signature payload is about the
// subject digest, like cosign verify does by default.
func checkLegacyClaims(signedPayload []byte, subject digest.Digest) error {
	var claims payload.SimpleContainerImage
	if err := json.Unmarshal(signedPayload, &claims); err != nil {
		return fmt.Errorf("decode signature payload: %w", err)
	}

	if claims.Critical.Image.DockerManifestDigest != subject.String() {
		return fmt.Errorf(
			"%w: payload is about %q",
			ErrSignatureDigestMismatch,
			claims.Critical.Image.DockerManifestDigest,
		)
	}

	return nil
}

// rekorBundle is the transparency log entry cosign attaches to legacy
// signatures.
type rekorBundle struct {
	SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
	Payload              struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		LogID          string `json:"logId"`
	} `json:"payload"`
}

// legacyBundle turns a legacy cosign signature into a Sigstore bundle v0.1
// with a message signature over the payload, so that it can be verified like
// a signature bundle.
func legacyBundle(annotations map[string]string, signedPayload []byte) (*sgbundle.Bundle, error) {
	sig, err := base64.StdEncoding.DecodeString(annotations[annotationLegacySignature])
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("%w: no signature", ErrInvalidSignatureBundle)
	}

	material := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{},
		},
	}

	if pemCert := annotations[annotationLegacyCertificate]; pemCert != "" {
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM([]byte(pemCert))
		if err != nil || len(certs) == 0 {
			return nil, fmt.Errorf("%w: invalid certificate", ErrInvalidSignatureBundle)
		}

		material.Content = &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: certs[0].Raw}},
			},
		}
	}

	if raw := annotations[annotationLegacyBundle]; raw != "" {
		entry, err := legacyTlogEntry([]byte(raw))
		if err != nil {
			return nil, err
		}

		material.TlogEntries = []*protorekor.TransparencyLogEntry{entry}
	}

	mediaType, err := sgbundle.MediaTypeString("0.1")
	if err != nil {
		return nil, err
	}

	payloadDigest := sha256.Sum256(signedPayload)

	bundle, err := sgbundle.NewBundle(&protobundle.Bundle{
		MediaType:            mediaType,
		VerificationMaterial: material,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    payloadDigest[:],
				},
				Signature: sig,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignatureBundle, err)
	}

	return bundle, nil
}

// legacyTlogEntry converts the transparency log bundle of a legacy signature
// into the transparency log entry of a Sigstore bundle.
func legacyTlogEntry(raw []byte) (*protorekor.TransparencyLogEntry, error) {
	var rekor rekorBundle
	if err := json.Unmarshal(raw, &rekor); err != nil {
		return nil, fmt.Errorf(
			"%w: decode transparency log bundle: %w",
			ErrInvalidSignatureBundle,
			err,
		)
	}

	body, err := base64.StdEncoding.DecodeString(rekor.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: decode transparency log entry: %w",
			ErrInvalidSignatureBundle,
			err,
		)
	}

	var kind struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(body, &kind); err != nil {
		return nil, fmt.Errorf(
			"%w: decode transparency log entry: %w",
			ErrInvalidSignatureBundle,
			err,
		)
	}

	logID, err := hex.DecodeString(rekor.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("%w: decode transparency log ID: %w", ErrInvalidSignatureBundle, err)
	}

	return &protorekor.TransparencyLogEntry{
		LogIndex:       rekor.Payload.LogIndex,
		LogId:          &protocommon.LogId{KeyId: logID},
		KindVersion:    &protorekor.KindVersion{Kind: kind.Kind, Version: kind.APIVersion},
		IntegratedTime: rekor.Payload.IntegratedTime,
		InclusionPromise: &protorekor.InclusionPromise{
			SignedEntryTimestamp: rekor.SignedEntryTimestamp,
		},
		CanonicalizedBody: body,
	}, nil
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
