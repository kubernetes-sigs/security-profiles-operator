package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x25519"
)

type keyType int

const (
	jwkKeyType keyType = iota
	pemKeyType
	octKeyType
)

// read returns the bytes from reading a file, or from a url if the filename has
// the prefix https://
func read(filename string) ([]byte, error) {
	if strings.HasPrefix(filename, "https://") {
		resp, err := http.Get(filename) //nolint:gosec // no SSRF
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving %s", filename)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			return nil, errors.Errorf("error retrieving %s: status code %d", filename, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		return b, errors.Wrapf(err, "error retrieving %s", filename)
	}

	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	return b, nil
}

// ReadKey returns a JSONWebKey from the given JWK or PEM file. If the file is
// password protected, and no password or prompt password function is given it
// will fail.
func ReadKey(filename string, opts ...Option) (*JSONWebKey, error) {
	b, err := read(filename)
	if err != nil {
		return nil, err
	}
	opts = append(opts, WithFilename(filename))
	return ParseKey(b, opts...)
}

// ParseKey returns a JSONWebKey from the given JWK file or a PEM file. If the
// file is password protected, and no password or prompt password function is
// given it will fail.
func ParseKey(b []byte, opts ...Option) (*JSONWebKey, error) {
	ctx, err := new(context).apply(opts...)
	if err != nil {
		return nil, err
	}
	if ctx.filename == "" {
		ctx.filename = "key"
	}

	jwk := new(JSONWebKey)
	switch guessKeyType(ctx, b) {
	case jwkKeyType:
		// Attempt to parse an encrypted file
		if b, err = Decrypt(b, opts...); err != nil {
			return nil, err
		}

		// Unmarshal the plain (or decrypted JWK)
		if err = json.Unmarshal(b, jwk); err != nil {
			return nil, errors.Errorf("error reading %s: unsupported format", ctx.filename)
		}

	// If KeyID not set by environment, then use the default.
	// NOTE: we do not set this value by default in the case of jwkKeyType
	// because it is assumed to have been left empty on purpose.
	case pemKeyType:
		pemOptions := []pemutil.Options{
			pemutil.WithFilename(ctx.filename),
		}
		if ctx.password != nil {
			pemOptions = append(pemOptions, pemutil.WithPassword(ctx.password))
		}
		if ctx.passwordPrompter != nil {
			pemOptions = append(pemOptions, pemutil.WithPasswordPrompt(ctx.passwordPrompt, pemutil.PasswordPrompter(ctx.passwordPrompter)))
		}
		if pemutil.PromptPassword == nil && PromptPassword != nil {
			pemutil.PromptPassword = pemutil.PasswordPrompter(PromptPassword)
		}

		jwk.Key, err = pemutil.ParseKey(b, pemOptions...)
		if err != nil {
			return nil, err
		}
		if ctx.kid == "" {
			if jwk.KeyID, err = Thumbprint(jwk); err != nil {
				return nil, err
			}
		}
	case octKeyType:
		jwk.Key = b
	}

	// Validate key id
	if ctx.kid != "" && jwk.KeyID != "" && ctx.kid != jwk.KeyID {
		return nil, errors.Errorf("kid %s does not match the kid on %s", ctx.kid, ctx.filename)
	}
	if jwk.KeyID == "" {
		jwk.KeyID = ctx.kid
	}
	if jwk.Use == "" {
		jwk.Use = ctx.use
	}

	// Set the algorithm if empty
	guessJWKAlgorithm(ctx, jwk)

	// Validate alg: if the flag '--subtle' is passed we will allow to overwrite it
	if !ctx.subtle && ctx.alg != "" && jwk.Algorithm != "" && ctx.alg != jwk.Algorithm {
		return nil, errors.Errorf("alg %s does not match the alg on %s", ctx.alg, ctx.filename)
	}
	if ctx.subtle && ctx.alg != "" {
		jwk.Algorithm = ctx.alg
	}

	return jwk, nil
}

// ReadKeySet reads a JWK Set from a URL or filename. URLs must start with
// "https://".
func ReadKeySet(filename string, opts ...Option) (*JSONWebKey, error) {
	b, err := read(filename)
	if err != nil {
		return nil, err
	}
	opts = append(opts, WithFilename(filename))
	return ParseKeySet(b, opts...)
}

// ParseKeySet returns the JWK with the given key after parsing a JWKSet from
// a given file.
func ParseKeySet(b []byte, opts ...Option) (*JSONWebKey, error) {
	ctx, err := new(context).apply(opts...)
	if err != nil {
		return nil, err
	}

	// Attempt to parse an encrypted file
	if b, err = Decrypt(b, opts...); err != nil {
		return nil, err
	}

	// Unmarshal the plain or decrypted JWKSet
	jwkSet := new(JSONWebKeySet)
	if err := json.Unmarshal(b, jwkSet); err != nil {
		return nil, errors.Errorf("error reading %s: unsupported format", ctx.filename)
	}

	jwks := jwkSet.Key(ctx.kid)
	switch len(jwks) {
	case 0:
		return nil, errors.Errorf("cannot find key with kid %s on %s", ctx.kid, ctx.filename)
	case 1:
		jwk := &jwks[0]

		// Set the algorithm if empty
		guessJWKAlgorithm(ctx, jwk)

		// Validate alg: if the flag '--subtle' is passed we will allow the
		// overwrite of the alg
		if !ctx.subtle && ctx.alg != "" && jwk.Algorithm != "" && ctx.alg != jwk.Algorithm {
			return nil, errors.Errorf("alg %s does not match the alg on %s", ctx.alg, ctx.filename)
		}
		if ctx.subtle && ctx.alg != "" {
			jwk.Algorithm = ctx.alg
		}
		return jwk, nil
	default:
		return nil, errors.Errorf("multiple keys with kid %s have been found on %s", ctx.kid, ctx.filename)
	}
}

func decodeCerts(l []interface{}) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(l))
	for i, j := range l {
		certStr, ok := j.(string)
		if !ok {
			return nil, errors.Errorf("wrong type in x5c header list; expected string but %T", i)
		}
		certB, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, errors.Wrap(err, "error decoding base64 encoded x5c cert")
		}
		cert, err := x509.ParseCertificate(certB)
		if err != nil {
			return nil, errors.Wrap(err, "error parsing x5c cert")
		}
		certs[i] = cert
	}
	return certs, nil
}

// X5cInsecureKey is the key used to store the x5cInsecure cert chain in the JWT header.
var X5cInsecureKey = "x5cInsecure"

// GetX5cInsecureHeader extracts the x5cInsecure certificate chain from the token.
func GetX5cInsecureHeader(jwt *JSONWebToken) ([]*x509.Certificate, error) {
	x5cVal, ok := jwt.Headers[0].ExtraHeaders[HeaderKey(X5cInsecureKey)]
	if !ok {
		return nil, errors.New("ssh check-host token missing x5cInsecure header")
	}
	interfaces, ok := x5cVal.([]interface{})
	if !ok {
		return nil, errors.Errorf("ssh check-host token x5cInsecure header has wrong type; expected []string, but got %T", x5cVal)
	}
	chain, err := decodeCerts(interfaces)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding x5cInsecure header certs")
	}
	return chain, nil
}

// ParseX5cInsecure parses an x5cInsecure token, validates the certificate chain
// in the token, and returns the JWT struct along with all the verified chains.
func ParseX5cInsecure(tok string, roots []*x509.Certificate) (*JSONWebToken, [][]*x509.Certificate, error) {
	jwt, err := ParseSigned(tok)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "error parsing x5cInsecure token")
	}

	chain, err := GetX5cInsecureHeader(jwt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error extracting x5cInsecure cert chain")
	}
	leaf := chain[0]

	interPool := x509.NewCertPool()
	for _, crt := range chain[1:] {
		interPool.AddCert(crt)
	}
	rootPool := x509.NewCertPool()
	for _, crt := range roots {
		rootPool.AddCert(crt)
	}
	// Correctly parse and validate the x5c certificate chain.
	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		// A hack so we skip validity period validation.
		CurrentTime: leaf.NotAfter.Add(-1 * time.Minute),
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "error verifying x5cInsecure certificate chain")
	}
	leaf = verifiedChains[0][0]

	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, nil, errors.New("certificate used to sign x5cInsecure token cannot be used for digital signature")
	}

	return jwt, verifiedChains, nil
}

// guessKeyType returns the key type of the given data. Key types are JWK, PEM
// or oct.
func guessKeyType(ctx *context, data []byte) keyType {
	switch ctx.alg {
	// jwk or file with oct data
	case "HS256", "HS384", "HS512":
		// Encrypted JWK ?
		if _, err := ParseEncrypted(string(data)); err == nil {
			return jwkKeyType
		}
		// JSON JWK ?
		if err := json.Unmarshal(data, &JSONWebKey{}); err == nil {
			return jwkKeyType
		}
		// Default to oct
		return octKeyType
	default:
		// PEM or default to JWK
		if bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return pemKeyType
		}
		return jwkKeyType
	}
}

// guessJWKAlgorithm set the algorithm if it's not set and we can guess it
func guessJWKAlgorithm(ctx *context, jwk *JSONWebKey) {
	if jwk.Algorithm == "" {
		// Force default algorithm if passed.
		if ctx.alg != "" {
			jwk.Algorithm = ctx.alg
			return
		}

		// Guess only fixed algorithms if no defaults is enabled
		if ctx.noDefaults {
			guessKnownJWKAlgorithm(ctx, jwk)
			return
		}

		// Use defaults for each key type
		switch k := jwk.Key.(type) {
		case []byte:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultOctKeyAlgorithm)
			} else {
				jwk.Algorithm = string(DefaultOctSigAlgorithm)
			}
		case *ecdsa.PrivateKey:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultECKeyAlgorithm)
			} else {
				jwk.Algorithm = getECAlgorithm(k.Curve)
			}
		case *ecdsa.PublicKey:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultECKeyAlgorithm)
			} else {
				jwk.Algorithm = getECAlgorithm(k.Curve)
			}
		case *rsa.PrivateKey, *rsa.PublicKey:
			if jwk.Use == "enc" {
				jwk.Algorithm = string(DefaultRSAKeyAlgorithm)
			} else {
				jwk.Algorithm = string(DefaultRSASigAlgorithm)
			}
		// Ed25519 can only be used for signing operations
		case ed25519.PrivateKey, ed25519.PublicKey:
			jwk.Algorithm = EdDSA
		case x25519.PrivateKey, x25519.PublicKey:
			jwk.Algorithm = XEdDSA
		}
	}
}

// guessSignatureAlgorithm returns the signature algorithm for a given private key.
func guessSignatureAlgorithm(key crypto.PrivateKey) SignatureAlgorithm {
	switch k := key.(type) {
	case []byte:
		return DefaultOctSigAlgorithm
	case *ecdsa.PrivateKey:
		return SignatureAlgorithm(getECAlgorithm(k.Curve))
	case *rsa.PrivateKey:
		return DefaultRSASigAlgorithm
	case ed25519.PrivateKey:
		return EdDSA
	case x25519.PrivateKey, X25519Signer:
		return XEdDSA
	default:
		return ""
	}
}

// guessKnownJWKAlgorithm sets the algorithm for keys that only have one
// possible algorithm.
func guessKnownJWKAlgorithm(ctx *context, jwk *JSONWebKey) {
	if jwk.Algorithm == "" && jwk.Use != "enc" {
		switch k := jwk.Key.(type) {
		case *ecdsa.PrivateKey:
			jwk.Algorithm = getECAlgorithm(k.Curve)
		case *ecdsa.PublicKey:
			jwk.Algorithm = getECAlgorithm(k.Curve)
		case ed25519.PrivateKey, ed25519.PublicKey:
			jwk.Algorithm = EdDSA
		case x25519.PrivateKey, x25519.PublicKey:
			jwk.Algorithm = XEdDSA
		}
	}
}

// getECAlgorithm returns the JWA algorithm name for the given elliptic curve.
// If the curve is not supported it will return an empty string.
//
// Supported curves are P-256, P-384, and P-521.
func getECAlgorithm(crv elliptic.Curve) string {
	switch crv.Params().Name {
	case P256:
		return ES256
	case P384:
		return ES384
	case P521:
		return ES512
	default:
		return ""
	}
}
