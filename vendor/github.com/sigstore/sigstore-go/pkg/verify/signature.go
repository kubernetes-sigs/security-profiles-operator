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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

var ErrDSSEInvalidSignatureCount = errors.New("exactly one signature is required")

func VerifySignature(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelope(verifier, envelope)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return errors.New("artifact must be provided to verify message signature")
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content has neither an envelope or a message")
}

func VerifySignatureWithArtifact(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifact io.Reader) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifact(verifier, envelope, artifact)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignature(verifier, msg, artifact)
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content has neither an envelope or a message")
}

func VerifySignatureWithArtifactDigest(sigContent SignatureContent, verificationContent VerificationContent, trustedMaterial root.TrustedMaterial, artifactDigest []byte, artifactDigestAlgorithm string) error { // nolint: revive
	var verifier signature.Verifier
	var err error

	verifier, err = getSignatureVerifier(verificationContent, trustedMaterial)
	if err != nil {
		return fmt.Errorf("could not load signature verifier: %w", err)
	}

	if envelope := sigContent.EnvelopeContent(); envelope != nil {
		return verifyEnvelopeWithArtifactDigest(verifier, envelope, artifactDigest, artifactDigestAlgorithm)
	} else if msg := sigContent.MessageSignatureContent(); msg != nil {
		return verifyMessageSignatureWithArtifactDigest(verifier, msg, artifactDigest)
	}

	// handle an invalid signature content message
	return fmt.Errorf("signature content has neither an envelope or a message")
}

func getSignatureVerifier(verificationContent VerificationContent, tm root.TrustedMaterial) (signature.Verifier, error) {
	if leafCert := verificationContent.GetCertificate(); leafCert != nil {
		// TODO: Inspect certificate's SignatureAlgorithm to determine hash function
		return signature.LoadVerifier(leafCert.PublicKey, crypto.SHA256)
	} else if pk, ok := verificationContent.HasPublicKey(); ok {
		return tm.PublicKeyVerifier(pk.Hint())
	}

	return nil, fmt.Errorf("no public key or certificate found")
}

func verifyEnvelope(verifier signature.Verifier, envelope EnvelopeContent) error {
	dsseEnv := envelope.RawEnvelope()

	// A DSSE envelope in a Sigstore bundle MUST only contain one
	// signature, even though DSSE is more permissive.
	if len(dsseEnv.Signatures) != 1 {
		return ErrDSSEInvalidSignatureCount
	}
	pub, err := verifier.PublicKey()
	if err != nil {
		return fmt.Errorf("could not fetch verifier public key: %w", err)
	}
	envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
		SignatureVerifier: verifier,
		Pub:               pub,
	})

	if err != nil {
		return fmt.Errorf("could not load envelope verifier: %w", err)
	}

	_, err = envVerifier.Verify(context.TODO(), dsseEnv)
	if err != nil {
		return fmt.Errorf("could not verify envelope: %w", err)
	}

	return nil
}

func verifyEnvelopeWithArtifact(verifier signature.Verifier, envelope EnvelopeContent, artifact io.Reader) error {
	err := verifyEnvelope(verifier, envelope)
	if err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	var artifactDigestAlgorithm string
	var artifactDigest []byte

	// Determine artifact digest algorithm by looking at the first subject's
	// digests. This assumes that if a statement contains multiple subjects,
	// they all use the same digest algorithm(s).
	if len(statement.Subject) == 0 {
		return errors.New("no subjects found in statement")
	}
	if len(statement.Subject[0].Digest) == 0 {
		return errors.New("no digests found in statement")
	}

	// Select the strongest digest algorithm available.
	for _, alg := range []string{"sha512", "sha384", "sha256"} {
		if _, ok := statement.Subject[0].Digest[alg]; ok {
			artifactDigestAlgorithm = alg
			continue
		}
	}
	if artifactDigestAlgorithm == "" {
		return errors.New("could not verify artifact: unsupported digest algorithm")
	}

	// Compute digest of the artifact.
	var hasher hash.Hash
	switch artifactDigestAlgorithm {
	case "sha512":
		hasher = crypto.SHA512.New()
	case "sha384":
		hasher = crypto.SHA384.New()
	case "sha256":
		hasher = crypto.SHA256.New()
	}
	_, err = io.Copy(hasher, artifact)
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to calculate digest: %w", err)
	}
	artifactDigest = hasher.Sum(nil)

	// Look for artifact digest in statement
	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			hexdigest, err := hex.DecodeString(digest)
			if err != nil {
				return fmt.Errorf("could not verify artifact: unable to decode subject digest: %w", err)
			}
			if alg == artifactDigestAlgorithm && bytes.Equal(artifactDigest, hexdigest) {
				return nil
			}
		}
	}
	return fmt.Errorf("could not verify artifact: unable to confirm artifact digest is present in subject digests: %w", err)
}

func verifyEnvelopeWithArtifactDigest(verifier signature.Verifier, envelope EnvelopeContent, artifactDigest []byte, artifactDigestAlgorithm string) error {
	err := verifyEnvelope(verifier, envelope)
	if err != nil {
		return err
	}
	statement, err := envelope.Statement()
	if err != nil {
		return fmt.Errorf("could not verify artifact: unable to extract statement from envelope: %w", err)
	}
	for _, subject := range statement.Subject {
		for alg, digest := range subject.Digest {
			if alg == artifactDigestAlgorithm {
				hexdigest, err := hex.DecodeString(digest)
				if err != nil {
					return fmt.Errorf("could not verify artifact: unable to decode subject digest: %w", err)
				}
				if bytes.Equal(hexdigest, artifactDigest) {
					return nil
				}
			}
		}
	}
	return errors.New("provided artifact digest does not match any digest in statement")
}

func verifyMessageSignature(verifier signature.Verifier, msg MessageSignatureContent, artifact io.Reader) error {
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), artifact)
	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}

func verifyMessageSignatureWithArtifactDigest(verifier signature.Verifier, msg MessageSignatureContent, artifactDigest []byte) error {
	if !bytes.Equal(artifactDigest, msg.Digest()) {
		return errors.New("artifact does not match digest")
	}
	if _, ok := verifier.(*signature.ED25519Verifier); ok {
		return errors.New("message signatures with ed25519 signatures can only be verified with artifacts, and not just their digest")
	}
	err := verifier.VerifySignature(bytes.NewReader(msg.Signature()), bytes.NewReader([]byte{}), options.WithDigest(artifactDigest))

	if err != nil {
		return fmt.Errorf("could not verify message: %w", err)
	}

	return nil
}
