package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RFC 7515 - X.509 Certificate SHA-1 Thumbprint
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"go.step.sm/crypto/keyutil"
	"golang.org/x/crypto/ssh"
)

// ValidateSSHPOP validates the given SSH certificate and key for use in an
// sshpop header.
func ValidateSSHPOP(certFile string, key interface{}) (string, error) {
	if certFile == "" {
		return "", errors.New("ssh certfile cannot be empty")
	}
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return "", errors.Wrapf(err, "error reading ssh certificate from %s", certFile)
	}
	sshpub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return "", errors.Wrapf(err, "error parsing ssh public key from %s", certFile)
	}
	cert, ok := sshpub.(*ssh.Certificate)
	if !ok {
		return "", errors.New("error casting ssh public key to ssh certificate")
	}
	pubkey, err := keyutil.ExtractKey(cert)
	if err != nil {
		return "", errors.Wrap(err, "error extracting public key from ssh public key interface")
	}
	if err = validateKeyPair(pubkey, key); err != nil {
		return "", errors.Wrap(err, "error verifying ssh key pair")
	}

	return base64.StdEncoding.EncodeToString(cert.Marshal()), nil
}

func validateKeyPair(pub crypto.PublicKey, priv crypto.PrivateKey) error {
	switch key := priv.(type) {
	case *JSONWebKey:
		return keyutil.VerifyPair(pub, key.Key)
	case OpaqueSigner:
		if !keyutil.Equal(pub, key.Public().Key) {
			return errors.New("private key does not match public key")
		}
		return nil
	default:
		return keyutil.VerifyPair(pub, priv)
	}
}

func validateX5(certs []*x509.Certificate, key interface{}) error {
	if len(certs) == 0 {
		return errors.New("certs cannot be empty")
	}

	if err := validateKeyPair(certs[0].PublicKey, key); err != nil {
		return errors.Wrap(err, "error verifying certificate and key")
	}

	if certs[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate/private-key pair used to sign " +
			"token is not approved for digital signature")
	}
	return nil
}

// ValidateX5C validates the given certificate chain and key for use as a token
// signer and x5t header.
func ValidateX5C(certs []*x509.Certificate, key interface{}) ([]string, error) {
	if err := validateX5(certs, key); err != nil {
		return nil, errors.Wrap(err, "ValidateX5C")
	}
	strs := make([]string, len(certs))
	for i, cert := range certs {
		strs[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return strs, nil
}

// ValidateX5T validates the given certificate and key for use as a token signer
// and x5t header.
func ValidateX5T(certs []*x509.Certificate, key interface{}) (string, error) {
	if err := validateX5(certs, key); err != nil {
		return "", errors.Wrap(err, "ValidateX5T")
	}
	// x5t is the base64 URL encoded SHA1 thumbprint
	// (see https://tools.ietf.org/html/rfc7515#section-4.1.7)
	//nolint:gosec // RFC 7515 - X.509 Certificate SHA-1 Thumbprint
	fingerprint := sha1.Sum(certs[0].Raw)
	return base64.URLEncoding.EncodeToString(fingerprint[:]), nil
}

// ValidateJWK validates the given JWK.
func ValidateJWK(jwk *JSONWebKey) error {
	switch jwk.Use {
	case "sig":
		return validateSigJWK(jwk)
	case "enc":
		return validateEncJWK(jwk)
	default:
		return validateGeneric(jwk)
	}
}

// validateSigJWK validates the given JWK for signature operations.
func validateSigJWK(jwk *JSONWebKey) error {
	if jwk.Algorithm == "" {
		return errors.New("flag '--alg' is required with the given key")
	}
	errctx := "the given key"

	switch k := jwk.Key.(type) {
	case []byte:
		switch jwk.Algorithm {
		case HS256, HS384, HS512:
			return nil
		}
		errctx = "kty 'oct'"
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch jwk.Algorithm {
		case RS256, RS384, RS512:
			return nil
		case PS256, PS384, PS512:
			return nil
		}
		errctx = "kty 'RSA'"
	case *ecdsa.PrivateKey:
		curve := k.Params().Name
		switch {
		case jwk.Algorithm == ES256 && curve == P256:
			return nil
		case jwk.Algorithm == ES384 && curve == P384:
			return nil
		case jwk.Algorithm == ES512 && curve == P521:
			return nil
		}
		errctx = fmt.Sprintf("kty 'EC' and crv '%s'", curve)
	case *ecdsa.PublicKey:
		curve := k.Params().Name
		switch {
		case jwk.Algorithm == ES256 && curve == P256:
			return nil
		case jwk.Algorithm == ES384 && curve == P384:
			return nil
		case jwk.Algorithm == ES512 && curve == P521:
			return nil
		}
		errctx = fmt.Sprintf("kty 'EC' and crv '%s'", curve)
	case ed25519.PrivateKey, ed25519.PublicKey:
		if jwk.Algorithm == EdDSA {
			return nil
		}
		errctx = "kty 'OKP' and crv 'Ed25519'"
	}

	return errors.Errorf("alg '%s' is not compatible with %s", jwk.Algorithm, errctx)
}

// validatesEncJWK validates the given JWK for encryption operations.
func validateEncJWK(jwk *JSONWebKey) error {
	alg := KeyAlgorithm(jwk.Algorithm)
	var kty string

	switch jwk.Key.(type) {
	case []byte:
		switch alg {
		case DIRECT, A128GCMKW, A192GCMKW, A256GCMKW, A128KW, A192KW, A256KW:
			return nil
		}
		kty = "oct"
	case *rsa.PrivateKey, *rsa.PublicKey:
		switch alg {
		case RSA1_5, RSA_OAEP, RSA_OAEP_256:
			return nil
		}
		kty = "RSA"
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		switch alg {
		case ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW:
			return nil
		}
		kty = "EC"
	case ed25519.PrivateKey, ed25519.PublicKey:
		return errors.New("key Ed25519 cannot be used for encryption")
	}

	return errors.Errorf("alg '%s' is not compatible with kty '%s'", jwk.Algorithm, kty)
}

// validateGeneric validates just the supported key types.
func validateGeneric(jwk *JSONWebKey) error {
	switch jwk.Key.(type) {
	case []byte:
		return nil
	case *rsa.PrivateKey, *rsa.PublicKey:
		return nil
	case *ecdsa.PrivateKey, *ecdsa.PublicKey:
		return nil
	case ed25519.PrivateKey, ed25519.PublicKey:
		return nil
	}

	return errors.Errorf("unsupported key type '%T'", jwk.Key)
}
