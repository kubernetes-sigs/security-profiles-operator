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
	"fmt"
	"os"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// allowAllRegexp is the default signer regexp, which accepts any signer.
const allowAllRegexp = ".*"

// Options define all possible options for the puller.
type Options struct {
	pullFrom                     string
	outputFile                   string
	outputFileSet                bool
	username                     string
	password                     string
	platform                     *v1.Platform
	disableSignatureVerification bool
	allowedIdentityRegexp        string
	allowedOidcIssuerRegexp      string
	keyRef                       string
	certIdentity                 string
	certOidcIssuer               string
	trustedRootPath              string
	offline                      bool
	plainHTTP                    bool
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		outputFile:              DefaultOutputFile,
		allowedIdentityRegexp:   allowAllRegexp,
		allowedOidcIssuerRegexp: allowAllRegexp,
	}
}

// Flags returns the flags of the pull command.
func Flags() []ucli.Flag {
	return append([]ucli.Flag{
		&ucli.StringFlag{
			Name:        FlagOutputFile,
			Aliases:     []string{"o"},
			Usage:       "the output file to store the profile",
			DefaultText: DefaultOutputFile,
			TakesFile:   true,
		},
		&ucli.StringFlag{
			Name:    FlagPlatform,
			Aliases: []string{"p", flagPlatformsAlias},
			Usage:   "the platform to be used in format: os[/arch][/variant][:os_version]",
		},
		&ucli.BoolFlag{
			Name:    FlagDisableSignatureVerification,
			Aliases: []string{"s"},
			// The unprefixed variable is the former name, kept working.
			EnvVars: []string{
				"SPOC_DISABLE_SIGNATURE_VERIFICATION",
				"DISABLE_SIGNATURE_VERIFICATION",
			},
			Usage: "disable signature verification",
		},
		&ucli.StringFlag{
			Name:    FlagAllowedIdentityRegexp,
			Aliases: []string{"i"},
			// The unprefixed variable is the former name, kept working.
			EnvVars:     []string{"SPOC_ALLOWED_IDENTITY_REGEXP", "ALLOWED_IDENTITIES_REGEXP"},
			Usage:       "regexp for allowed identities in signature verification",
			DefaultText: allowAllRegexp,
		},
		&ucli.StringFlag{
			Name: FlagAllowedOidcIssuerRegexp,
			// The unprefixed variable is the former name, kept working.
			EnvVars:     []string{"SPOC_ALLOWED_OIDC_ISSUER_REGEXP", "ALLOWED_OIDC_ISSUER_REGEXP"},
			Usage:       "regexp for allowed OIDC issuers in signature verification",
			DefaultText: allowAllRegexp,
		},
		&ucli.StringFlag{
			Name:    FlagCertificateIdentity,
			EnvVars: []string{"SPOC_CERTIFICATE_IDENTITY"},
			Usage: "exact identity the signature certificate has to carry, " +
				"takes precedence over the identity regexp",
		},
		&ucli.StringFlag{
			Name:    FlagCertificateOidcIssuer,
			EnvVars: []string{"SPOC_CERTIFICATE_OIDC_ISSUER"},
			Usage: "exact OIDC issuer of the signature certificate, " +
				"takes precedence over the issuer regexp",
		},
		&ucli.StringFlag{
			Name:    FlagKey,
			Aliases: []string{"k"},
			EnvVars: []string{"SPOC_KEY"},
			Usage: "verify the signature with the public key instead of a " +
				"keyless certificate: the path of a PEM encoded public key, " +
				"cannot be combined with the identity and issuer flags",
			TakesFile: true,
		},
		&ucli.StringFlag{
			Name:    FlagTrustedRoot,
			EnvVars: []string{"SPOC_TRUSTED_ROOT"},
			Usage: "path of a Sigstore trusted root JSON file to verify against " +
				"instead of the one distributed through TUF",
			TakesFile: true,
		},
		&ucli.BoolFlag{
			Name:    FlagOffline,
			EnvVars: []string{"SPOC_OFFLINE"},
			Usage: "verify with the trusted root cached from TUF instead of refreshing it, " +
				"an empty cache needs --trusted-root or one run without --offline",
		},
	}, cli.RegistryFlags()...)
}

// checkSigner rejects a public key together with identity or issuer
// constraints, which would otherwise be ignored silently.
func (o *Options) checkSigner() error {
	if o.keyRef == "" {
		return nil
	}

	var conflicting []string

	if o.certIdentity != "" {
		conflicting = append(conflicting, "--"+FlagCertificateIdentity)
	}

	if o.certOidcIssuer != "" {
		conflicting = append(conflicting, "--"+FlagCertificateOidcIssuer)
	}

	if !isDefaultRegexp(o.allowedIdentityRegexp) {
		conflicting = append(conflicting, "--"+FlagAllowedIdentityRegexp)
	}

	if !isDefaultRegexp(o.allowedOidcIssuerRegexp) {
		conflicting = append(conflicting, "--"+FlagAllowedOidcIssuerRegexp)
	}

	if len(conflicting) == 0 {
		return nil
	}

	return fmt.Errorf(
		"%w: --%s cannot be combined with %s",
		ErrKeyWithIdentity, FlagKey, strings.Join(conflicting, ", "),
	)
}

// isDefaultRegexp reports whether the signer regexp accepts any signer, the
// default which does not constrain a key signature.
func isDefaultRegexp(pattern string) bool {
	return pattern == "" || pattern == allowAllRegexp
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *ucli.Context) (*Options, error) {
	options := Default()

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no remote image provided")
	}

	options.pullFrom = args[0]

	if ctx.IsSet(FlagOutputFile) {
		options.outputFile = ctx.String(FlagOutputFile)
		options.outputFileSet = true
	}

	if options.outputFile == "" {
		return nil, errors.New("no filename provided")
	}

	if ctx.IsSet(FlagDisableSignatureVerification) {
		options.disableSignatureVerification = ctx.Bool(FlagDisableSignatureVerification)
	}

	if ctx.IsSet(FlagAllowedIdentityRegexp) {
		options.allowedIdentityRegexp = ctx.String(FlagAllowedIdentityRegexp)
	}

	if ctx.IsSet(FlagAllowedOidcIssuerRegexp) {
		options.allowedOidcIssuerRegexp = ctx.String(FlagAllowedOidcIssuerRegexp)
	}

	options.keyRef = ctx.String(FlagKey)
	options.certIdentity = ctx.String(FlagCertificateIdentity)
	options.certOidcIssuer = ctx.String(FlagCertificateOidcIssuer)
	options.trustedRootPath = ctx.String(FlagTrustedRoot)
	options.offline = ctx.Bool(FlagOffline)
	options.plainHTTP = ctx.Bool(FlagPlainHTTP)

	if err := options.checkSigner(); err != nil {
		return nil, err
	}

	username, password, err := cli.RegistryCredentials(ctx, os.Stdin, os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("get registry credentials: %w", err)
	}

	options.username = username
	options.password = password

	platform, err := cli.ParsePlatform(ctx.String(FlagPlatform))
	if err != nil {
		return nil, fmt.Errorf("parse platform: %w", err)
	}

	options.platform = platform

	return options, nil
}
