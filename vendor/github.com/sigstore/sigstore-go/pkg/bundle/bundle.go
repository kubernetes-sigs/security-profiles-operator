// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var ErrValidation = errors.New("validation error")
var ErrUnsupportedMediaType = fmt.Errorf("%w: unsupported media type", ErrValidation)
var ErrMissingVerificationMaterial = fmt.Errorf("%w: missing verification material", ErrValidation)
var ErrUnimplemented = errors.New("unimplemented")
var ErrInvalidAttestation = fmt.Errorf("%w: invalid attestation", ErrValidation)
var ErrMissingEnvelope = fmt.Errorf("%w: missing envelope", ErrInvalidAttestation)
var ErrDecodingJSON = fmt.Errorf("%w: decoding json", ErrInvalidAttestation)
var ErrDecodingB64 = fmt.Errorf("%w: decoding base64", ErrInvalidAttestation)

const mediaTypeBase = "application/vnd.dev.sigstore.bundle"

func ErrValidationError(err error) error {
	return fmt.Errorf("%w: %w", ErrValidation, err)
}

type ProtobufBundle struct {
	*protobundle.Bundle
	hasInclusionPromise bool
	hasInclusionProof   bool
}

func NewProtobufBundle(pbundle *protobundle.Bundle) (*ProtobufBundle, error) {
	bundle := &ProtobufBundle{
		Bundle:              pbundle,
		hasInclusionPromise: false,
		hasInclusionProof:   false,
	}

	err := bundle.validate()
	if err != nil {
		return nil, err
	}

	return bundle, nil
}

func (b *ProtobufBundle) validate() error {
	bundleVersion, err := getBundleVersion(b.Bundle.MediaType)
	if err != nil {
		return fmt.Errorf("error getting bundle version: %w", err)
	}

	// if bundle version is < 0.1, return error
	if semver.Compare(bundleVersion, "v0.1") < 0 {
		return fmt.Errorf("%w: bundle version %s is not supported", ErrUnsupportedMediaType, bundleVersion)
	}

	// fetch tlog entries, as next check needs to check them for inclusion proof/promise
	entries, err := b.TlogEntries()
	if err != nil {
		return err
	}

	// if bundle version == v0.1, require inclusion promise
	if semver.Compare(bundleVersion, "v0.1") == 0 {
		if len(entries) > 0 && !b.hasInclusionPromise {
			return errors.New("inclusion promises missing in bundle (required for bundle v0.1)")
		}
	} else {
		// if bundle version >= v0.2, require inclusion proof
		if len(entries) > 0 && !b.hasInclusionProof {
			return errors.New("inclusion proof missing in bundle (required for bundle v0.2)")
		}
	}

	// if bundle version >= v0.3, require verification material to not be X.509 certificate chain (only single certificate is allowed)
	if semver.Compare(bundleVersion, "v0.3") >= 0 {
		certs := b.Bundle.VerificationMaterial.GetX509CertificateChain()

		if certs != nil {
			return errors.New("verification material cannot be X.509 certificate chain (for bundle v0.3)")
		}
	}

	// if bundle version is >= v0.4, return error as this version is not supported
	if semver.Compare(bundleVersion, "v0.4") >= 0 {
		return fmt.Errorf("%w: bundle version %s is not yet supported", ErrUnsupportedMediaType, bundleVersion)
	}

	return nil
}

// MediaTypeString returns a mediatype string for the specified bundle version.
// The function returns an error if the resulting string does validate.
func MediaTypeString(version string) (string, error) {
	if version == "" {
		return "", fmt.Errorf("unable to build media type string, no version defined")
	}

	var mtString string

	version = strings.TrimPrefix(version, "v")
	mtString = fmt.Sprintf("%s.v%s+json", mediaTypeBase, strings.TrimPrefix(version, "v"))

	if version == "0.1" || version == "0.2" {
		mtString = fmt.Sprintf("%s+json;version=%s", mediaTypeBase, strings.TrimPrefix(version, "v"))
	}

	if _, err := getBundleVersion(mtString); err != nil {
		return "", fmt.Errorf("unable to build mediatype: %w", err)
	}

	return mtString, nil
}

func getBundleVersion(mediaType string) (string, error) {
	switch mediaType {
	case mediaTypeBase + "+json;version=0.1":
		return "v0.1", nil
	case mediaTypeBase + "+json;version=0.2":
		return "v0.2", nil
	case mediaTypeBase + "+json;version=0.3":
		return "v0.3", nil
	}
	if strings.HasPrefix(mediaType, mediaTypeBase+".v") && strings.HasSuffix(mediaType, "+json") {
		version := strings.TrimPrefix(mediaType, mediaTypeBase+".")
		version = strings.TrimSuffix(version, "+json")
		if semver.IsValid(version) {
			return version, nil
		}
		return "", fmt.Errorf("%w: invalid bundle version: %s", ErrUnsupportedMediaType, version)
	}
	return "", fmt.Errorf("%w: %s", ErrUnsupportedMediaType, mediaType)
}

func LoadJSONFromPath(path string) (*ProtobufBundle, error) {
	var bundle ProtobufBundle
	bundle.Bundle = new(protobundle.Bundle)

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = bundle.UnmarshalJSON(contents)
	if err != nil {
		return nil, err
	}

	return &bundle, nil
}

func (b *ProtobufBundle) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(b.Bundle)
}

func (b *ProtobufBundle) UnmarshalJSON(data []byte) error {
	b.Bundle = new(protobundle.Bundle)
	err := protojson.Unmarshal(data, b.Bundle)
	if err != nil {
		return err
	}

	err = b.validate()
	if err != nil {
		return err
	}

	return nil
}

func (b *ProtobufBundle) VerificationContent() (verify.VerificationContent, error) {
	if b.VerificationMaterial == nil {
		return nil, ErrMissingVerificationMaterial
	}

	switch content := b.VerificationMaterial.GetContent().(type) {
	case *protobundle.VerificationMaterial_X509CertificateChain:
		certs := content.X509CertificateChain.GetCertificates()
		if len(certs) == 0 {
			return nil, ErrMissingVerificationMaterial
		}
		parsedCert, err := x509.ParseCertificate(certs[0].RawBytes)
		if err != nil {
			return nil, ErrValidationError(err)
		}
		cert := &Certificate{
			Certificate: parsedCert,
		}
		return cert, nil
	case *protobundle.VerificationMaterial_Certificate:
		parsedCert, err := x509.ParseCertificate(content.Certificate.RawBytes)
		if err != nil {
			return nil, ErrValidationError(err)
		}
		cert := &Certificate{
			Certificate: parsedCert,
		}
		return cert, nil
	case *protobundle.VerificationMaterial_PublicKey:
		pk := &PublicKey{
			hint: content.PublicKey.Hint,
		}
		return pk, nil

	default:
		return nil, ErrMissingVerificationMaterial
	}
}

func (b *ProtobufBundle) HasInclusionPromise() bool {
	return b.hasInclusionPromise
}

func (b *ProtobufBundle) HasInclusionProof() bool {
	return b.hasInclusionProof
}

func (b *ProtobufBundle) TlogEntries() ([]*tlog.Entry, error) {
	if b.VerificationMaterial == nil {
		return nil, nil
	}

	tlogEntries := make([]*tlog.Entry, len(b.VerificationMaterial.TlogEntries))
	var err error
	for i, entry := range b.VerificationMaterial.TlogEntries {
		tlogEntries[i], err = tlog.ParseEntry(entry)
		if err != nil {
			return nil, ErrValidationError(err)
		}

		if tlogEntries[i].HasInclusionPromise() {
			b.hasInclusionPromise = true
		}
		if tlogEntries[i].HasInclusionProof() {
			b.hasInclusionProof = true
		}
	}

	return tlogEntries, nil
}

func (b *ProtobufBundle) SignatureContent() (verify.SignatureContent, error) {
	switch content := b.Bundle.Content.(type) { //nolint:gocritic
	case *protobundle.Bundle_DsseEnvelope:
		envelope, err := parseEnvelope(content.DsseEnvelope)
		if err != nil {
			return nil, err
		}
		return envelope, nil
	case *protobundle.Bundle_MessageSignature:
		return NewMessageSignature(
			content.MessageSignature.MessageDigest.Digest,
			protocommon.HashAlgorithm_name[int32(content.MessageSignature.MessageDigest.Algorithm)],
			content.MessageSignature.Signature,
		), nil
	}
	return nil, ErrMissingVerificationMaterial
}

func (b *ProtobufBundle) Envelope() (*Envelope, error) {
	switch content := b.Bundle.Content.(type) { //nolint:gocritic
	case *protobundle.Bundle_DsseEnvelope:
		envelope, err := parseEnvelope(content.DsseEnvelope)
		if err != nil {
			return nil, err
		}
		return envelope, nil
	}
	return nil, ErrMissingVerificationMaterial
}

func (b *ProtobufBundle) Timestamps() ([][]byte, error) {
	if b.VerificationMaterial == nil {
		return nil, ErrMissingVerificationMaterial
	}

	signedTimestamps := make([][]byte, 0)

	if b.VerificationMaterial.TimestampVerificationData == nil {
		return signedTimestamps, nil
	}

	for _, timestamp := range b.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps {
		signedTimestamps = append(signedTimestamps, timestamp.SignedTimestamp)
	}

	return signedTimestamps, nil
}

// MinVersion returns true if the bundle version is greater than or equal to the expected version.
func (b *ProtobufBundle) MinVersion(expectVersion string) bool {
	version, err := getBundleVersion(b.Bundle.MediaType)
	if err != nil {
		return false
	}

	if !strings.HasPrefix(expectVersion, "v") {
		expectVersion = "v" + expectVersion
	}

	return semver.Compare(version, expectVersion) >= 0
}

func parseEnvelope(input *protodsse.Envelope) (*Envelope, error) {
	output := &dsse.Envelope{}
	output.Payload = base64.StdEncoding.EncodeToString([]byte(input.GetPayload()))
	output.PayloadType = string(input.GetPayloadType())
	output.Signatures = make([]dsse.Signature, len(input.GetSignatures()))
	for i, sig := range input.GetSignatures() {
		output.Signatures[i].KeyID = sig.GetKeyid()
		output.Signatures[i].Sig = base64.StdEncoding.EncodeToString(sig.GetSig())
	}
	return &Envelope{Envelope: output}, nil
}
