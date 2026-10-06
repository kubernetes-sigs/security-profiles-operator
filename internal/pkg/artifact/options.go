/*
Copyright The Kubernetes Authors.

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

package artifact

import (
	"strings"
)

const allowAllRegexp = ".*"

// PullOptions are the options for pulling an OCI artifact: how to reach the
// registry and how to verify the artifact's signature.
type PullOptions struct {
	// DisableSignatureVerification disables signature verification during pulling.
	DisableSignatureVerification bool

	// PlainHTTP talks to the registry over HTTP instead of HTTPS, for local
	// registries in tests. Signature verification then uses HTTP as well.
	PlainHTTP bool

	// AllowedIdentityRegexp regexp for allowed identities for signature verification.
	//
	// The default ".*" matches every identity, which means any valid keyless
	// signature is accepted no matter who produced it. Set this to the
	// identities you actually trust. Artifacts of the official repositories
	// are verified against OfficialSignerIdentityRegexp instead, as long as
	// both regexps are left at the default.
	AllowedIdentityRegexp string

	// AllowedOidcIssuerRegexp regexp for allowed Oidc issuer for signature verification.
	//
	// As with AllowedIdentityRegexp, the default ".*" matches every issuer.
	AllowedOidcIssuerRegexp string

	// KeyRef verifies the signature with a public key instead of a keyless
	// certificate: the path of a PEM encoded public key, like the cosign.pub
	// of `cosign generate-key-pair`. The identity and issuer constraints do
	// not apply to key signatures.
	KeyRef string

	// KeyPEM is the PEM encoded public key itself, for callers which hold it
	// in memory. It takes precedence over KeyRef and verifies the same way.
	KeyPEM []byte

	// CertIdentity is the exact identity the keyless signature certificate
	// has to carry. It takes precedence over AllowedIdentityRegexp. For the
	// official repositories, the issuer stays pinned to the official one
	// unless CertOidcIssuer or AllowedOidcIssuerRegexp is set as well.
	CertIdentity string

	// CertOidcIssuer is the exact OIDC issuer of the keyless signature
	// certificate. It takes precedence over AllowedOidcIssuerRegexp. For the
	// official repositories, the identity stays pinned to the official one
	// unless CertIdentity or AllowedIdentityRegexp is set as well.
	CertOidcIssuer string

	// TrustedRootPath is the path of a Sigstore trusted root JSON file to
	// verify against instead of the one distributed through TUF, for
	// private Sigstore deployments and air-gapped environments.
	TrustedRootPath string

	// TrustedRootJSON is the content of a Sigstore trusted root JSON file,
	// for callers which hold it in memory. It takes precedence over
	// TrustedRootPath.
	TrustedRootJSON []byte

	// Offline verifies with the trusted root cached on disk as long as its
	// TUF metadata has not expired, instead of refreshing it. The
	// transparency log entry bundled with the signature is verified in any
	// case, it is never looked up online.
	Offline bool

	// MaxBlobSize is the largest blob of the artifact, in bytes, the pull
	// copies from the registry. Bigger blobs fail the pull before they are
	// fetched. Zero means DefaultMaxBlobSize.
	MaxBlobSize int64
}

// maxBlobSize returns the blob size limit to apply on pull.
func (p *PullOptions) maxBlobSize() int64 {
	if p.MaxBlobSize > 0 {
		return p.MaxBlobSize
	}

	return DefaultMaxBlobSize
}

// PushOptions are the options for pushing an OCI artifact.
type PushOptions struct {
	// DisableSigning skips signing the artifact after it has been pushed.
	// Keyless signing needs an OIDC identity, which build systems and test
	// environments do not necessarily have.
	DisableSigning bool

	// DisableArtifactValidation skips the validation container runtimes
	// apply to a KEP-6061 artifact, so that deliberately invalid profiles
	// can be published for testing. Runtimes still reject them when pulled.
	DisableArtifactValidation bool

	// PlainHTTP talks to the registry over HTTP instead of HTTPS, for local
	// registries in tests. Signing then uses HTTP as well.
	PlainHTTP bool

	// OIDCDeviceFlow signs in to the OIDC provider with the device flow if
	// the environment furnishes no identity token and stdin is not a
	// terminal. Without it, signing fails right away then, instead of
	// waiting for a sign in nobody may be there to complete.
	OIDCDeviceFlow bool
}

// SignOptions are the options for signing an OCI artifact which is already
// in the registry.
type SignOptions struct {
	// PlainHTTP talks to the registry over HTTP instead of HTTPS, for local
	// registries in tests.
	PlainHTTP bool

	// OIDCDeviceFlow is the device flow opt-in of PushOptions.
	OIDCDeviceFlow bool
}

// withDefaultSigner returns a copy of the options with the signer constraints
// for the image. Artifacts of the official repositories are verified against
// the official signers when the caller left both regexps at the default, which
// accepts any signer. An exact identity or issuer replaces only its own part
// of the official signer, the other part stays pinned to the official one.
// Every other combination, and a public key, is kept as given.
func (p *PullOptions) withDefaultSigner(image string) *PullOptions {
	opts := *p

	if opts.hasKey() ||
		!isDefaultRegexp(opts.AllowedIdentityRegexp) ||
		!isDefaultRegexp(opts.AllowedOidcIssuerRegexp) {
		return &opts
	}

	if isOfficialArtifact(image) {
		if opts.CertIdentity == "" {
			opts.AllowedIdentityRegexp = OfficialSignerIdentityRegexp
		}

		if opts.CertOidcIssuer == "" {
			opts.AllowedOidcIssuerRegexp = OfficialSignerOidcIssuerRegexp
		}

		return &opts
	}

	opts.AllowedIdentityRegexp = allowAllRegexp
	opts.AllowedOidcIssuerRegexp = allowAllRegexp

	return &opts
}

// Signer returns the identity and OIDC issuer regexps a pull of the image
// verifies its signature against, which differ from the configured ones for
// the official repositories.
func (p *PullOptions) Signer(image string) (identity, issuer string) {
	opts := p.withDefaultSigner(image)

	return opts.AllowedIdentityRegexp, opts.AllowedOidcIssuerRegexp
}

// isDefaultRegexp reports whether the signer regexp is the default, which is
// empty or the ".*" of the spoc flags and the SPOD API.
func isDefaultRegexp(pattern string) bool {
	return pattern == "" || pattern == allowAllRegexp
}

// IsOfficialArtifact reports whether the image belongs to one of the
// repositories this project publishes to, whose artifacts are signed keyless by
// the official signers through the public Sigstore instance.
func IsOfficialArtifact(image string) bool {
	return isOfficialArtifact(image)
}

// isOfficialArtifact reports whether the image belongs to one of the
// repositories this project publishes to.
func isOfficialArtifact(image string) bool {
	for _, prefix := range officialRepositories {
		if strings.HasPrefix(image, prefix) {
			return true
		}
	}

	return false
}

// hasExplicitSigner reports whether the caller pinned the signer to a key or
// an exact identity or issuer, which replaces the official signer of the
// official repositories, at least in part.
func (p *PullOptions) hasExplicitSigner() bool {
	return p.hasKey() || p.CertIdentity != "" || p.CertOidcIssuer != ""
}

// hasKey reports whether the signature is verified with a public key instead
// of a keyless certificate.
func (p *PullOptions) hasKey() bool {
	return p.KeyRef != "" || len(p.KeyPEM) > 0
}

// hasTrustedRoot reports whether the caller replaced the trusted root of TUF.
func (p *PullOptions) hasTrustedRoot() bool {
	return p.TrustedRootPath != "" || len(p.TrustedRootJSON) > 0
}

// hasCustomSigner reports whether the caller replaced the official signer or
// the public Sigstore trusted root, which the official repositories are
// verified against by default.
func (p *PullOptions) hasCustomSigner() bool {
	return p.hasExplicitSigner() || p.hasTrustedRoot()
}

// hasUnconstrainedSigner reports whether the signer identity or the OIDC
// issuer is left unconstrained, in which case verification does not establish
// who signed the artifact. A public key pins the signer by itself, and an
// exact identity or issuer constrains its part.
func (p *PullOptions) hasUnconstrainedSigner() bool {
	if p.hasKey() {
		return false
	}

	return (p.CertIdentity == "" && matchesAnything(p.AllowedIdentityRegexp)) ||
		(p.CertOidcIssuer == "" && matchesAnything(p.AllowedOidcIssuerRegexp))
}

// matchesAnything reports whether pattern accepts every value. Deciding that in
// general is not possible, so this recognises the shipped default and the
// spellings equivalent to it. A false result therefore means "not obviously
// unconstrained" rather than "constrained".
func matchesAnything(pattern string) bool {
	switch strings.TrimSpace(pattern) {
	case "", allowAllRegexp, ".+", "^.*$", "^.+$", "(.*)", "(.+)", "^", "$":
		return true
	}

	return false
}
