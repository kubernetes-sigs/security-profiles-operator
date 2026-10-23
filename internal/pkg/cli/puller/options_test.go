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
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

func TestFromContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *flag.FlagSet)
		assert  func(*testing.T, *Options, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, opts *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.False(t, opts.disableSignatureVerification)
			},
		},
		{
			name: "failure username without password",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(cli.FlagUsername, "", "")
				require.NoError(t, set.Set(cli.FlagUsername, "username"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorIs(t, err, cli.ErrIncompleteCredentials)
			},
		},
		{
			name: "success with verify signature disabled",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.Bool(FlagDisableSignatureVerification, true, "")
				require.NoError(t, set.Set(FlagDisableSignatureVerification, "true"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, opts *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, opts.disableSignatureVerification)
			},
		},
		{
			name: "success with verify allowed identity and allowed oidc issuer regexp(s)",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagAllowedIdentityRegexp, "testIdentity*", "")
				set.String(FlagAllowedOidcIssuerRegexp, "testOidc*", "")
				require.NoError(t, set.Set(FlagAllowedIdentityRegexp, "testIdentity*"))
				require.NoError(t, set.Set(FlagAllowedOidcIssuerRegexp, "testOidc*"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, opts *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "testIdentity*", opts.allowedIdentityRegexp)
				require.Equal(t, "testOidc*", opts.allowedOidcIssuerRegexp)
			},
		},
		{
			name: "success with key, trusted root and offline",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagKey, "", "")
				set.String(FlagAllowedIdentityRegexp, "", "")
				set.String(FlagTrustedRoot, "", "")
				set.Bool(FlagOffline, false, "")
				require.NoError(t, set.Set(FlagKey, "cosign.pub"))
				// The default regexp does not constrain anything.
				require.NoError(t, set.Set(FlagAllowedIdentityRegexp, ".*"))
				require.NoError(t, set.Set(FlagTrustedRoot, "root.json"))
				require.NoError(t, set.Set(FlagOffline, "true"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, opts *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "cosign.pub", opts.keyRef)
				require.Equal(t, "root.json", opts.trustedRootPath)
				require.True(t, opts.offline)
			},
		},
		{
			name: "success with exact signer",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagCertificateIdentity, "", "")
				set.String(FlagCertificateOidcIssuer, "", "")
				require.NoError(t, set.Set(FlagCertificateIdentity, "me@example.com"))
				require.NoError(t, set.Set(FlagCertificateOidcIssuer, "https://issuer"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, opts *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "me@example.com", opts.certIdentity)
				require.Equal(t, "https://issuer", opts.certOidcIssuer)
			},
		},
		{
			name: "failure key with exact signer",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagKey, "", "")
				set.String(FlagCertificateIdentity, "", "")
				set.String(FlagCertificateOidcIssuer, "", "")
				require.NoError(t, set.Set(FlagKey, "cosign.pub"))
				require.NoError(t, set.Set(FlagCertificateIdentity, "me@example.com"))
				require.NoError(t, set.Set(FlagCertificateOidcIssuer, "https://issuer"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrKeyWithIdentity)
				require.ErrorContains(t, err, "--"+FlagCertificateIdentity)
				require.ErrorContains(t, err, "--"+FlagCertificateOidcIssuer)
			},
		},
		{
			name: "failure key with signer regexp",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagKey, "", "")
				set.String(FlagAllowedOidcIssuerRegexp, "", "")
				require.NoError(t, set.Set(FlagKey, "cosign.pub"))
				require.NoError(t, set.Set(FlagAllowedOidcIssuerRegexp, "^https://issuer$"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrKeyWithIdentity)
				require.ErrorContains(t, err, "--"+FlagAllowedOidcIssuerRegexp)
			},
		},
		{
			name: "failure no image provided",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Set(FlagOutputFile, ""))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "no remote image provided")
			},
		},
		{
			name: "failure no output file provided",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Set(FlagOutputFile, ""))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "no filename provided")
			},
		},
		{
			name: "failure parse platform",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagPlatform, "", "")
				require.NoError(t, set.Set(FlagPlatform, "os//var"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "parse platform")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			prepare(t, set)

			app := ucli.NewApp()
			ctx := ucli.NewContext(app, set, nil)

			opts, err := FromContext(ctx)
			assert(t, opts, err)
		})
	}
}
