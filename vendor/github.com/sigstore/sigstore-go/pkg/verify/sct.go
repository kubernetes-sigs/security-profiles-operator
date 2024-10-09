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
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// VerifySignedCertificateTimestamp, given a threshold, TrustedMaterial, and a
// leaf certificate, will extract SCTs from the leaf certificate and verify the
// timestamps using the TrustedMaterial's FulcioCertificateAuthorities() and
// CTLogs()
func VerifySignedCertificateTimestamp(leafCert *x509.Certificate, threshold int, trustedMaterial root.TrustedMaterial) error { // nolint: revive
	ctlogs := trustedMaterial.CTLogs()
	fulcioCerts := trustedMaterial.FulcioCertificateAuthorities()

	scts, err := x509util.ParseSCTsFromCertificate(leafCert.Raw)
	if err != nil {
		return err
	}

	leafCTCert, err := ctx509.ParseCertificates(leafCert.Raw)
	if err != nil {
		return err
	}

	verified := 0
	for _, sct := range scts {
		encodedKeyID := hex.EncodeToString(sct.LogID.KeyID[:])
		key, ok := ctlogs[encodedKeyID]
		if !ok {
			// skip entries the trust root cannot verify
			continue
		}

		for _, fulcioCa := range fulcioCerts {
			fulcioChain := make([]*ctx509.Certificate, len(leafCTCert))
			copy(fulcioChain, leafCTCert)

			var parentCert []byte

			if len(fulcioCa.Intermediates) == 0 {
				parentCert = fulcioCa.Root.Raw
			} else {
				parentCert = fulcioCa.Intermediates[0].Raw
			}

			fulcioIssuer, err := ctx509.ParseCertificates(parentCert)
			if err != nil {
				continue
			}
			fulcioChain = append(fulcioChain, fulcioIssuer...)

			err = ctutil.VerifySCT(key.PublicKey, fulcioChain, sct, true)
			if err == nil {
				verified++
			}
		}
	}

	if verified < threshold {
		return fmt.Errorf("only able to verify %d SCT entries; unable to meet threshold of %d", verified, threshold)
	}

	return nil
}
