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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
)

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
