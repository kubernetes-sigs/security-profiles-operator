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
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	tsaverification "github.com/sigstore/timestamp-authority/pkg/verification"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const maxAllowedTimestamps = 32

// VerifyTimestampAuthority verifies that the given entity has been timestamped
// by a trusted timestamp authority and that the timestamp is valid.
func VerifyTimestampAuthority(entity SignedEntity, trustedMaterial root.TrustedMaterial) ([]time.Time, error) { //nolint:revive
	signedTimestamps, err := entity.Timestamps()
	if err != nil {
		return nil, err
	}

	// limit the number of timestamps to prevent DoS
	if len(signedTimestamps) > maxAllowedTimestamps {
		return nil, fmt.Errorf("too many signed timestamps: %d > %d", len(signedTimestamps), maxAllowedTimestamps)
	}

	// disallow duplicate timestamps, as a malicious actor could use duplicates to bypass the threshold
	for i := 0; i < len(signedTimestamps); i++ {
		for j := i + 1; j < len(signedTimestamps); j++ {
			if bytes.Equal(signedTimestamps[i], signedTimestamps[j]) {
				return nil, errors.New("duplicate timestamps found")
			}
		}
	}

	sigContent, err := entity.SignatureContent()
	if err != nil {
		return nil, err
	}

	signatureBytes := sigContent.Signature()

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		return nil, err
	}

	verifiedTimestamps := []time.Time{}
	for _, timestamp := range signedTimestamps {
		verifiedSignedTimestamp, err := verifySignedTimestamp(timestamp, signatureBytes, trustedMaterial, verificationContent)

		// Timestamps from unknown source are okay, but don't count as verified
		if err != nil {
			continue
		}

		verifiedTimestamps = append(verifiedTimestamps, verifiedSignedTimestamp)
	}

	return verifiedTimestamps, nil
}

// VerifyTimestampAuthority verifies that the given entity has been timestamped
// by a trusted timestamp authority and that the timestamp is valid.
//
// The threshold parameter is the number of unique timestamps that must be
// verified.
func VerifyTimestampAuthorityWithThreshold(entity SignedEntity, trustedMaterial root.TrustedMaterial, threshold int) ([]time.Time, error) { //nolint:revive
	verifiedTimestamps, err := VerifyTimestampAuthority(entity, trustedMaterial)
	if err != nil {
		return nil, err
	}
	if len(verifiedTimestamps) < threshold {
		return nil, fmt.Errorf("threshold not met for verified signed timestamps: %d < %d", len(verifiedTimestamps), threshold)
	}
	return verifiedTimestamps, nil
}

func verifySignedTimestamp(signedTimestamp []byte, dsseSignatureBytes []byte, trustedMaterial root.TrustedMaterial, verificationContent VerificationContent) (time.Time, error) {
	certAuthorities := trustedMaterial.TimestampingAuthorities()

	// Iterate through TSA certificate authorities to find one that verifies
	for _, ca := range certAuthorities {
		trustedRootVerificationOptions := tsaverification.VerifyOpts{
			Roots:          []*x509.Certificate{ca.Root},
			Intermediates:  ca.Intermediates,
			TSACertificate: ca.Leaf,
		}

		// Ensure timestamp responses are from trusted sources
		timestamp, err := tsaverification.VerifyTimestampResponse(signedTimestamp, bytes.NewReader(dsseSignatureBytes), trustedRootVerificationOptions)
		if err != nil {
			continue
		}

		if !ca.ValidityPeriodStart.IsZero() && timestamp.Time.Before(ca.ValidityPeriodStart) {
			continue
		}
		if !ca.ValidityPeriodEnd.IsZero() && timestamp.Time.After(ca.ValidityPeriodEnd) {
			continue
		}

		// Check tlog entry time against bundle certificates
		// TODO: technically no longer needed since we check the cert validity period in the main Verify loop
		if !verificationContent.ValidAtTime(timestamp.Time, trustedMaterial) {
			continue
		}

		// All above verification successful, so return nil
		return timestamp.Time, nil
	}

	return time.Time{}, errors.New("unable to verify signed timestamps")
}
