/*
Copyright 2025 The Sigstore Authors.

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

// Heavily borrowed from https://gist.githubusercontent.com/AlCutter/c6c69076dc55652e2d278900ccc1a5e7/raw/aac2bafc17a8efa162bd99b4453070b724779307/ecdsa_note.go - thanks, Al

package note

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/transparency-dev/formats/log"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

const (
	algEd25519 = 1
	algMLDSA44 = 6
	algUndef   = 255
	rsaID      = "PKIX-RSA-PKCS#1v1.5"
)

// noteSigner uses an arbitrary sigstore signer to implement golang.org/x/mod/sumdb/note.Signer,
// which is used in Tessera to sign checkpoints in the signed notes format
// (https://github.com/C2SP/C2SP/blob/main/signed-note.md).
type noteSigner struct {
	name string
	hash uint32
	sign func(msg []byte) ([]byte, error)
}

// Name returns the server name associated with the key.
func (n *noteSigner) Name() string {
	return n.name
}

// KeyHash returns the key hash.
func (n *noteSigner) KeyHash() uint32 {
	return n.hash
}

// Sign returns a signature for the given message.
func (n *noteSigner) Sign(msg []byte) ([]byte, error) {
	return n.sign(msg)
}

type noteVerifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

// Name implements note.Verifier.
func (n *noteVerifier) Name() string {
	return n.name
}

// Keyhash implements note.Verifier.
func (n *noteVerifier) KeyHash() uint32 {
	return n.hash
}

// Verify implements note.Verifier.
func (n *noteVerifier) Verify(msg, sig []byte) bool {
	return n.verify(msg, sig)
}

// isValidName reports whether the name conforms to the spec for the origin string of the note text
// as defined in https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md#note-text.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

// genConformantKeyHash generates a truncated (4-byte) and non-truncated
// identifier for typical (non-ECDSA) keys.
func genConformantKeyHash(name string, sigType, key []byte) (uint32, []byte) {
	hash := sha256.New()
	hash.Write([]byte(name))
	hash.Write([]byte("\n"))
	hash.Write(sigType)
	hash.Write(key)
	sum := hash.Sum(nil)
	return binary.BigEndian.Uint32(sum), sum
}

// ed25519KeyHash generates the 4-byte key ID for an Ed25519 public key.
func ed25519KeyHash(name string, key []byte) (uint32, []byte) {
	return genConformantKeyHash(name, []byte{algEd25519}, key)
}

// ecdsaKeyHash generates the 4-byte key ID for an ECDSA public key.
// ECDSA key IDs do not conform to the note standard for other key type
// (see https://github.com/C2SP/C2SP/blob/8991f70ddf8a11de3a68d5a081e7be27e59d87c8/signed-note.md#signature-types).
func ecdsaKeyHash(key *ecdsa.PublicKey) (uint32, []byte, error) {
	marshaled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling public key: %w", err)
	}
	hash := sha256.Sum256(marshaled)
	return binary.BigEndian.Uint32(hash[:]), hash[:], nil
}

// rsaKeyhash generates the 4-byte key ID for an RSA public key.
func rsaKeyHash(name string, key *rsa.PublicKey) (uint32, []byte, error) {
	marshaled, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling public key: %w", err)
	}
	rsaAlg := append([]byte{algUndef}, []byte(rsaID)...)
	id, hash := genConformantKeyHash(name, rsaAlg, marshaled)
	return id, hash, nil
}

// mldsaKeyHash generates the 4-byte key ID for an ML-DSA-44 public key.
func mldsaKeyHash(name string, key *mldsa.PublicKey) (uint32, []byte, error) {
	if key.Parameters() != mldsa.MLDSA44() {
		return 0, nil, fmt.Errorf("unsupported ML-DSA parameter set %v, only ML-DSA-44 is supported", key.Parameters())
	}
	id, hash := genConformantKeyHash(name, []byte{algMLDSA44}, key.Bytes())
	return id, hash, nil
}

// KeyHash generates a truncated (4-byte) and non-truncated identifier for a
// public key/origin
func KeyHash(origin string, key crypto.PublicKey) (uint32, []byte, error) {
	var keyID uint32
	var logID []byte
	var err error

	switch pk := key.(type) {
	case *ecdsa.PublicKey:
		keyID, logID, err = ecdsaKeyHash(pk)
		if err != nil {
			return 0, nil, fmt.Errorf("getting ECDSA key hash: %w", err)
		}
	case ed25519.PublicKey:
		keyID, logID = ed25519KeyHash(origin, pk)
	case *rsa.PublicKey:
		keyID, logID, err = rsaKeyHash(origin, pk)
		if err != nil {
			return 0, nil, fmt.Errorf("getting RSA key hash: %w", err)
		}
	case *mldsa.PublicKey:
		keyID, logID, err = mldsaKeyHash(origin, pk)
		if err != nil {
			return 0, nil, fmt.Errorf("getting ML-DSA key hash: %w", err)
		}
	default:
		return 0, nil, fmt.Errorf("unsupported key type: %T", key)
	}

	return keyID, logID, nil
}

// formatCosignatureV1 formats a checkpoint into a c2sp.org/tlog-cosignature subtree/v1 message.
func formatCosignatureV1(origin string, timestamp uint64, msg []byte) ([]byte, error) {
	var c log.Checkpoint
	rest, err := c.Unmarshal(msg)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint format: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("checkpoint has unexpected trailing data")
	}
	if len(c.Hash) != sha256.Size {
		return nil, fmt.Errorf("invalid checkpoint hash length: %d", len(c.Hash))
	}

	b := cryptobyte.NewBuilder(nil)
	b.AddBytes([]byte("subtree/v1\n\x00"))
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(origin)) // 1 byte length-prefixed origin
	})
	b.AddUint64(timestamp) // timestamp
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(c.Origin)) // 1 byte length-prefixed log origin
	})
	b.AddUint64(0)      // start, always zero for a checkpoint
	b.AddUint64(c.Size) // end, always size of a log for a checkpoint
	b.AddBytes(c.Hash)  // current root hash
	return b.Bytes()
}

// NewNoteSigner converts a sigstore/sigstore/pkg/signature.Signer into a note.Signer.
func NewNoteSigner(ctx context.Context, origin string, signer signature.Signer) (note.Signer, error) {
	if !isValidName(origin) {
		return nil, fmt.Errorf("invalid name %s", origin)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	keyID, _, err := KeyHash(origin, pubKey)
	if err != nil {
		return nil, err
	}

	sign := func(msg []byte) ([]byte, error) {
		if _, isMLDSA := pubKey.(*mldsa.PublicKey); isMLDSA {
			// For ML-DSA, the format of the signed message is defined in c2sp.org/tlog-cosignature
			now := time.Now().Unix()
			if now < 0 {
				return nil, fmt.Errorf("invalid timestamp")
			}
			t := uint64(now)
			formattedMsg, err := formatCosignatureV1(origin, t, msg)
			if err != nil {
				return nil, err
			}

			sig, err := signer.SignMessage(bytes.NewReader(formattedMsg), options.WithContext(ctx))
			if err != nil {
				return nil, err
			}

			// signature is the raw signature prefixed with the timestamp
			finalSig := make([]byte, 8, 8+len(sig))
			binary.BigEndian.PutUint64(finalSig, t)
			finalSig = append(finalSig, sig...)
			return finalSig, nil
		}
		// For Ed25519 and other algorithms, signature is over the note text as defined in c2sp.org/tlog-checkpoint
		return signer.SignMessage(bytes.NewReader(msg), options.WithContext(ctx))
	}

	return &noteSigner{
		name: origin,
		hash: keyID,
		sign: sign,
	}, nil
}

// NewNoteVerifier converts a sigstore/sigstore/pkg/signature.Verifier into a note.Verifier.
func NewNoteVerifier(origin string, verifier signature.Verifier) (note.Verifier, error) {
	if !isValidName(origin) {
		return nil, fmt.Errorf("invalid name %s", origin)
	}

	pubKey, err := verifier.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	keyID, _, err := KeyHash(origin, pubKey)
	if err != nil {
		return nil, err
	}

	return &noteVerifier{
		name: origin,
		hash: keyID,
		verify: func(msg, sig []byte) bool {
			if mldsaPub, isMLDSA := pubKey.(*mldsa.PublicKey); isMLDSA {
				if len(sig) != 8+mldsaPub.Parameters().SignatureSize() {
					return false
				}
				t := binary.BigEndian.Uint64(sig[:8])
				sig = sig[8:]

				formattedMsg, err := formatCosignatureV1(origin, t, msg)
				if err != nil {
					return false
				}
				msg = formattedMsg
			}

			if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)); err != nil {
				return false
			}
			return true
		},
	}, nil
}
