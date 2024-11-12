/*
Wrapper APIs for in-toto attestation ResourceDescriptor protos.
*/

package v1

import (
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrIncorrectDigestLength = errors.New("digest has incorrect length")
	ErrInvalidDigestEncoding = errors.New("digest is not valid hex-encoded string")
	ErrRDRequiredField       = errors.New("at least one of name, URI, or digest are required")
)

// Indicates if a given fixed-size hash algorithm is supported by default and returns the algorithm's
// digest size in bytes, if supported. We assume gitCommit and dirHash are aliases for sha1 and sha256, respectively.
//
// SHA digest sizes from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
// MD5 digest size from https://www.rfc-editor.org/rfc/rfc1321.html#section-1
func isSupportedFixedSizeAlgorithm(alg string) (bool, int) {
	algos := map[string]int{"md5": 16, "sha1": 20, "sha224": 28, "sha512_224": 28, "sha256": 32, "sha512_256": 32, "sha384": 48, "sha512": 64, "sha3_224": 28, "sha3_256": 32, "sha3_384": 48, "sha3_512": 64, "gitCommit": 20, "dirHash": 32}

	size, ok := algos[alg]
	return ok, size
}

func (d *ResourceDescriptor) Validate() error {
	// at least one of name, URI or digest are required
	if d.GetName() == "" && d.GetUri() == "" && len(d.GetDigest()) == 0 {
		return ErrRDRequiredField
	}

	if len(d.GetDigest()) > 0 {
		for alg, digest := range d.GetDigest() {

			// Per https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md
			// check encoding and length for supported algorithms;
			// use of custom, unsupported algorithms is allowed and does not not generate validation errors.
			supported, size := isSupportedFixedSizeAlgorithm(alg)
			if supported {
				// the in-toto spec expects a hex-encoded string in DigestSets for supported algorithms
				hashBytes, err := hex.DecodeString(digest)

				if err != nil {
					return fmt.Errorf("%w (%s: %s)", ErrInvalidDigestEncoding, alg, digest)
				}

				// check the length of the digest
				if len(hashBytes) != size {
					return fmt.Errorf("%w: got %d bytes, want %d bytes (%s: %s)", ErrIncorrectDigestLength, len(hashBytes), size, alg, digest)
				}
			}
		}
	}

	return nil
}
