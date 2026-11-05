// Copyright 2022 The Sigstore Authors.
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

package x509

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var (
	// EKUOID is the Extended Key Usage OID, per RFC 5280
	EKUOID             = asn1.ObjectIdentifier{2, 5, 29, 37}
	EKUTimestampingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	// PolicyOID is the sigstore TSA's baseline time-stamp policy OID, used by
	// classical signers.
	PolicyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	// PolicyOIDPQC is the sigstore TSA's post-quantum time-stamp policy OID,
	// used by ML-DSA signers.
	PolicyOIDPQC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2, 1}
)

// VerifyCertChain verifies that the certificate chain is valid for issuing
// timestamping certificates. The chain should start with a leaf certificate,
// followed by any number of intermediates, and end with the root certificate.
func VerifyCertChain(certs []*x509.Certificate, signer crypto.Signer, enforceIntermediateEku bool) error {
	// Chain must contain at least one CA certificate and a leaf certificate
	if len(certs) == 0 || certs[0] == nil {
		return errors.New("certificate chain must contain a leaf certificate")
	}
	leaf := certs[0]

	if len(certs) < 2 {
		return errors.New("certificate chain must contain at least two certificates")
	}

	if signer == nil {
		return errors.New("signer must not be nil")
	}

	roots := x509.NewCertPool()
	roots.AddCert(certs[len(certs)-1])

	intermediates := x509.NewCertPool()
	if len(certs) > 2 {
		for _, intermediate := range certs[1 : len(certs)-1] {
			intermediates.AddCert(intermediate)
		}
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageTimeStamping,
		},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}

	// Verify that all certificates but the leaf are CA certificates
	for _, c := range certs[1:] {
		if !c.IsCA {
			return errors.New("certificate is not a CA certificate")
		}
	}

	// Verify the leaf is an end-entity certificate, per RFC 3161 2.3. The chain
	// verification above does not reject a CA certificate used as the leaf.
	if leaf.IsCA {
		return errors.New("leaf certificate must be an end-entity certificate, not a CA")
	}

	// Verify leaf has only a single EKU for timestamping, per RFC 3161 2.3
	// This should be enforced by Verify already. Key purposes that crypto/x509
	// does not recognise land in UnknownExtKeyUsage, so count those too.
	if len(leaf.ExtKeyUsage)+len(leaf.UnknownExtKeyUsage) != 1 {
		return errors.New("certificate should only contain one EKU")
	}

	// Verify leaf's EKU is set to critical, per RFC 3161 2.3
	var criticalEKU bool
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(EKUOID) {
			criticalEKU = ext.Critical
			break
		}
	}
	if !criticalEKU {
		return errors.New("certificate must set EKU to critical")
	}

	if enforceIntermediateEku && len(certs) > 2 {
		// If the chain contains intermediates, verify that the extended key
		// usage includes the extended key usage timestamping for EKU chaining
		for _, c := range certs[1 : len(certs)-1] {
			var hasExtKeyUsageTimeStamping bool
			if slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
				hasExtKeyUsageTimeStamping = true
			}
			if !hasExtKeyUsageTimeStamping {
				return errors.New(`certificate must have extended key usage timestamping set to sign timestamping certificates`)
			}
		}
	}

	// Verify the signer's public key matches the leaf certificate
	if err := cryptoutils.EqualKeys(leaf.PublicKey, signer.Public()); err != nil {
		return err
	}

	// Verify that the chain does not mix ML-DSA and non-ML-DSA public keys.
	_, signerIsMLDSA := signer.Public().(*mldsa.PublicKey)
	for _, c := range certs {
		if _, certIsMLDSA := c.PublicKey.(*mldsa.PublicKey); certIsMLDSA != signerIsMLDSA {
			return errors.New("certificate chain must not mix ML-DSA and non-ML-DSA public keys")
		}
	}

	return nil
}
