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

package puller

import (
	"errors"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// DefaultOutputFile defines the default output location for the puller.
var DefaultOutputFile = cli.DefaultFile

const (
	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = cli.FlagOutputFile

	// FlagUsername is the flag for defining the username for registry
	// authentication.
	FlagUsername string = cli.FlagUsername

	// FlagPasswordStdin is the flag for reading the password for registry
	// authentication from stdin.
	FlagPasswordStdin string = cli.FlagPasswordStdin

	// FlagPlatform is the flag for defining the platform.
	FlagPlatform string = "platform"

	// FlagDisableSignatureVerification is the flag for disabling the signature
	// verification on pull.
	FlagDisableSignatureVerification string = "disable-signature-verification"

	// FlagAllowedIdentityRegexp is the flag for defining the allowed identity
	// regexp when verifying the image signature.
	FlagAllowedIdentityRegexp string = "allowed-identity-regexp"

	// FlagPlainHTTP is the flag for talking to the registry over HTTP.
	FlagPlainHTTP string = cli.FlagPlainHTTP

	// FlagAllowedOidcIssuerRegexp is the flag for defining the allowed Oidc issuers
	// regexp when verifying the image signature.
	FlagAllowedOidcIssuerRegexp string = "allowed-oidc-issuer-regexp"

	// FlagKey is the flag for verifying the image signature with a public
	// key instead of a keyless certificate.
	FlagKey string = "key"

	// FlagCertificateIdentity is the flag for the exact identity the
	// signature certificate has to carry.
	FlagCertificateIdentity string = "certificate-identity"

	// FlagCertificateOidcIssuer is the flag for the exact OIDC issuer of the
	// signature certificate.
	FlagCertificateOidcIssuer string = "certificate-oidc-issuer"

	// FlagTrustedRoot is the flag for the Sigstore trusted root file to
	// verify against.
	FlagTrustedRoot string = "trusted-root"

	// FlagOffline is the flag for verifying without any transparency log
	// lookup.
	FlagOffline string = "offline"

	// flagPlatformsAlias is the alias of FlagPlatform, the flag name of push.
	flagPlatformsAlias string = "platforms"
)

// ErrKeyWithIdentity is returned if a public key is combined with identity or
// issuer constraints, which a key signature has no certificate for.
var ErrKeyWithIdentity = errors.New(
	"a public key signature carries no identity or OIDC issuer to verify",
)
