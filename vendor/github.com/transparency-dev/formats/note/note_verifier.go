// Copyright 2021 Google LLC. All Rights Reserved.
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

// Package note provides note-compatible signature verifiers and signers.
package note

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// NewVerifier returns a verifier for the given key, if the key's algo is known.
func NewVerifier(key string) (note.Verifier, error) {
	parts := strings.SplitN(key, "+", 3)
	if got, want := len(parts), 3; got != want {
		return nil, fmt.Errorf("key has %d parts, expected %d: %q", got, want, key)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("key has invalid base64 %q: %v", parts[2], err)
	}
	if len(keyBytes) < 2 {
		return nil, fmt.Errorf("invalid key, key bytes too short")
	}

	switch keyBytes[0] {
	case algECDSAWithSHA256:
		return NewECDSAVerifier(key)
	case algEd25519CosignatureV1:
		return NewVerifierForCosignatureV1(key)
	case algRFC6962STH:
		return NewRFC6962Verifier(key)
	default:
		return note.NewVerifier(key)
	}
}

// verifier is a note-compatible verifier.
type verifier struct {
	name    string
	keyHash uint32
	v       func(msg, sig []byte) bool
}

// Name returns the name associated with the key this verifier is based on.
func (v *verifier) Name() string {
	return v.name
}

// KeyHash returns a truncated hash of the key this verifier is based on.
func (v *verifier) KeyHash() uint32 {
	return v.keyHash
}

// Verify checks that the provided sig is valid over msg for the key this verifier is based on.
func (v *verifier) Verify(msg, sig []byte) bool {
	return v.v(msg, sig)
}

// NewECDSAVerifier creates a new note verifier for checking ECDSA signatures over SHA256 digests.
// This implementation is compatible with the signature scheme used by the Sigstore Rékor Log.
//
// The key is expected to be provided as a string in the following form:
//
//	<key_name>+<key_hash>+<key_bytes>
//
// Where
//
//	<key_name> is a human readable identifier for the key, containing no whitespace or "+" symbols
//	<key_bytes> is base64 encoded blob starting with a 0x02 (algECDSAWithSHA256) byte and followed
//	    by the DER encoded public key in SPKI format.
//	<key_hash> is a 32bit hash of the key DER
//
// e.g.:
//
//	"rekor.sigstore.dev+12345678+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNhtmPtrWm3U1eQXBogSMdGvXwBcK5AW5i0hrZLOC96l+smGNM7nwZ4QvFK/4sueRoVj//QP22Ni4Qt9DPfkWLc=
func NewECDSAVerifier(key string) (note.Verifier, error) {
	parts := strings.SplitN(key, "+", 3)
	if got, want := len(parts), 3; got != want {
		return nil, fmt.Errorf("key has %d parts, expected %d: %q", got, want, key)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("key has invalid base64 %q: %v", parts[2], err)
	}
	if len(keyBytes) < 2 {
		return nil, fmt.Errorf("invalid key, key bytes too short")
	}
	if keyBytes[0] != algECDSAWithSHA256 {
		return nil, fmt.Errorf("key has incorrect type %d", keyBytes[0])
	}
	der := keyBytes[1:]
	kh := keyHashECDSA(der)

	khProvided, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid key, couldn't parse keyhash: %v", err)
	}
	if uint32(khProvided) != kh {
		return nil, fmt.Errorf("invalid keyhash %x, expected %x", khProvided, kh)
	}

	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse public key: %v", err)
	}
	ecdsaKey, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is a %T, expected an ECDSA key", k)
	}

	return &verifier{
		name: parts[0],
		v: func(msg, sig []byte) bool {
			dgst := sha256.Sum256(msg)
			return ecdsa.VerifyASN1(ecdsaKey, dgst[:], sig)
		},
		keyHash: kh,
	}, nil
}

func keyHashECDSA(i []byte) uint32 {
	h := sha256.Sum256(i)
	return binary.BigEndian.Uint32(h[:])
}
