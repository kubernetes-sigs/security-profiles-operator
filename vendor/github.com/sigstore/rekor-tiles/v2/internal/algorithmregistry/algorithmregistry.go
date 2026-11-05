// Copyright 2025 The Sigstore Authors
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

package algorithmregistry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"
	"reflect"
	"slices"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	// AllowedClientSigningAlgorithms is the default set of supported signing
	// algorithms for log entry signatures.
	AllowedClientSigningAlgorithms = []v1.PublicKeyDetails{
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256,
		v1.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256,
		v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
		v1.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
		v1.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
		v1.PublicKeyDetails_PKIX_ED25519_PH,
	}
	// AllowedIdentitySigningAlgorithms is the default set of supported signing
	// algorithms for identity log entry signatures.
	AllowedIdentitySigningAlgorithms = []v1.PublicKeyDetails{
		v1.PublicKeyDetails_PKIX_ED25519,
		v1.PublicKeyDetails_ML_DSA_44,
	}
)

type UnsupportedAlgorithm struct {
	Pub crypto.PublicKey
	Alg crypto.Hash
}

func (e *UnsupportedAlgorithm) Error() string {
	hash := "none"
	if e.Alg != crypto.Hash(0) {
		hash = e.Alg.String()
	}

	switch v := e.Pub.(type) {
	case *rsa.PublicKey:
		bits := v.Size() * 8
		return fmt.Sprintf("unsupported entry algorithm for RSA key, size %d, digest %s", bits, hash)
	case *ecdsa.PublicKey:
		name := v.Curve.Params().Name
		return fmt.Sprintf("unsupported entry algorithm for ECDSA key, curve %s, digest %s", name, hash)
	case ed25519.PublicKey:
		return fmt.Sprintf("unsupported entry algorithm for Ed25519 key, digest %s", hash)
	case *mldsa.PublicKey:
		return fmt.Sprintf("unsupported entry algorithm for ML-DSA key, parameter set %s, digest %s", v.Parameters(), hash)
	default:
		return fmt.Sprintf("unsupported key type %s, digest %s", reflect.TypeOf(v), hash)
	}
}

// AlgorithmRegistry accepts a list of algorithms as strings, parses and formats them into a registry.
func AlgorithmRegistry(algorithmOptions []string) (*signature.AlgorithmRegistryConfig, error) {
	return newAlgorithmRegistry(algorithmOptions, AllowedClientSigningAlgorithms)
}

// IdentityAlgorithmRegistry accepts a list of identity signing algorithms as strings, parses and formats them into a registry.
func IdentityAlgorithmRegistry(algorithmOptions []string) (*signature.AlgorithmRegistryConfig, error) {
	return newAlgorithmRegistry(algorithmOptions, AllowedIdentitySigningAlgorithms)
}

func newAlgorithmRegistry(algorithmOptions []string, allowedAlgorithms []v1.PublicKeyDetails) (*signature.AlgorithmRegistryConfig, error) {
	var algorithms []v1.PublicKeyDetails
	if len(algorithmOptions) == 0 {
		algorithms = allowedAlgorithms
	} else {
		for _, a := range algorithmOptions {
			algorithm, err := signature.ParseSignatureAlgorithmFlag(a)
			if err != nil {
				return nil, fmt.Errorf("parsing signature algorithm flag: %w", err)
			}
			allowed := slices.Contains(allowedAlgorithms, algorithm)
			if !allowed {
				return nil, fmt.Errorf("algorithm %s is not in the allowed set", a)
			}
			algorithms = append(algorithms, algorithm)
		}
	}
	algorithmRegistry, err := signature.NewAlgorithmRegistryConfig(algorithms)
	if err != nil {
		return nil, fmt.Errorf("getting algorithm registry: %w", err)
	}
	return algorithmRegistry, nil
}

// CheckEntryAlgorithms checks that the public key and algorithm details match
// and are allowed given an algorithm registry.
func CheckEntryAlgorithms(pubKey crypto.PublicKey, algDetails signature.AlgorithmDetails, algorithmRegistry *signature.AlgorithmRegistryConfig) (bool, error) {
	// Ensure the requested signature algorithm is in the set of supported client algorithms
	// (e.g. rejects RSA-PSS, which shares the same key type, size, and hash as RSA-PKCS1v15).
	if !slices.Contains(AllowedClientSigningAlgorithms, algDetails.GetSignatureAlgorithm()) {
		return false, nil
	}
	// Verify that the provided public key matches the parameters (key type, curve/size, and hash)
	// specified by algDetails.
	keyRegistry, err := signature.NewAlgorithmRegistryConfig([]v1.PublicKeyDetails{algDetails.GetSignatureAlgorithm()})
	if err != nil {
		return false, fmt.Errorf("getting key algorithm registry: %w", err)
	}
	keyMatches, err := keyRegistry.IsAlgorithmPermitted(pubKey, algDetails.GetHashType())
	if err != nil {
		return false, fmt.Errorf("checking if key matches algorithm details: %w", err)
	}
	if !keyMatches {
		return false, nil
	}
	// Verify that the public key and hash combination is permitted by the server's configured
	// algorithm registry.
	return CheckAlgorithm(pubKey, algDetails.GetHashType(), algorithmRegistry)
}

// CheckAlgorithm checks that the combination of public key and message
// digest algorithm are allowed given an algorithm registry.
func CheckAlgorithm(pubKey crypto.PublicKey, alg crypto.Hash, algorithmRegistry *signature.AlgorithmRegistryConfig) (bool, error) {
	isPermitted, err := algorithmRegistry.IsAlgorithmPermitted(pubKey, alg)
	if err != nil {
		return false, fmt.Errorf("checking if algorithm is permitted: %w", err)
	}
	if !isPermitted {
		return false, nil
	}
	return true, nil
}
