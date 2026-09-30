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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/term"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	// oidcAudience is the audience of the identity tokens Fulcio accepts.
	oidcAudience = "sigstore"

	// oidcClientID is the OAuth client of the Sigstore OIDC provider.
	oidcClientID = "sigstore"

	// envSigstoreIDToken passes an identity token explicitly.
	envSigstoreIDToken = "SIGSTORE_ID_TOKEN" //nolint:gosec // the name of the variable, not a token

	// envGitHubRequestToken and envGitHubRequestURL are set by GitHub
	// Actions for jobs with the id-token: write permission.
	envGitHubRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	envGitHubRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"

	// filesystemTokenPath is where cosign reads a mounted identity token
	// from, for example a projected service account token.
	filesystemTokenPath = "/var/run/sigstore/cosign/oidc-token" //nolint:gosec // a path, not a token

	// maxTokenSize bounds the identity token responses.
	maxTokenSize = 1 << 20

	// privacyStatement is what cosign shows before an interactive sign in.
	privacyStatement = `
	The sigstore service, hosted by sigstore a Series of LF Projects, LLC, is provided pursuant to ` +
		`the Hosted Project Tools Terms of Use, available at ` +
		`https://lfprojects.org/policies/hosted-project-tools-terms-of-use/.
	Note that if your submission includes personal data associated with this signed artifact, it will ` +
		`be part of an immutable record.
	This may include the email address associated with the account with which you authenticate your ` +
		`contractual Agreement.
	This information will be used for signing this artifact and will be stored in public transparency ` +
		`logs and cannot be removed later, and is subject to the Immutable Record notice at ` +
		`https://lfprojects.org/policies/hosted-project-tools-immutable-records/.
`
)

// tokenProvider furnishes an identity token from the environment. It returns
// ok false if it is not available there.
type tokenProvider struct {
	name    string
	provide func(context.Context) (token string, ok bool, err error)
}

// ambientTokenProviders are the sources of identity tokens in CI systems and
// cloud environments, in the order cosign tries them.
var ambientTokenProviders = []tokenProvider{
	{name: "github-actions", provide: githubActionsToken},
	{name: "envvar", provide: envToken},
	{name: "filesystem", provide: filesystemToken},
	{name: "google-workload-identity", provide: googleWorkloadIdentityToken},
}

// idToken returns an identity token for Fulcio: from the first provider of
// the environment which furnishes one, otherwise by signing in to the OIDC
// issuer in the browser, or with the device flow without a terminal.
func idToken(ctx context.Context, issuer string) (string, error) {
	var errs []error

	for _, provider := range ambientTokenProviders {
		token, ok, err := provider.provide(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", provider.name, err))

			continue
		}

		if ok {
			return token, nil
		}
	}

	// An environment which has an identity but fails to furnish it must not
	// fall back to an interactive sign in.
	if len(errs) > 0 {
		return "", fmt.Errorf("fetch ambient OIDC credentials: %w", errors.Join(errs...))
	}

	var getter oauthflow.TokenGetter = oauthflow.DefaultIDTokenGetter

	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, privacyStatement)
	} else {
		fmt.Fprintln(os.Stderr, "Non-interactive mode detected, using device flow.")

		getter = oauthflow.NewDeviceFlowTokenGetterForIssuer(issuer)
	}

	token, err := oauthflow.OIDConnect(issuer, oidcClientID, "", "", getter)
	if err != nil {
		return "", fmt.Errorf("authenticate at %s: %w", issuer, err)
	}

	return token.RawString, nil
}

// envToken returns the token of SIGSTORE_ID_TOKEN.
func envToken(context.Context) (token string, ok bool, err error) {
	token, ok = os.LookupEnv(envSigstoreIDToken)

	return token, ok, nil
}

// filesystemToken returns the token mounted at the path cosign reads.
func filesystemToken(context.Context) (token string, ok bool, err error) {
	if _, err := os.Stat(filesystemTokenPath); err != nil {
		return "", false, nil //nolint:nilerr // a missing token is not an error
	}

	raw, err := os.ReadFile(filesystemTokenPath)
	if err != nil {
		return "", false, err
	}

	return string(raw), true, nil
}

// githubActionsToken requests a token for the job from GitHub Actions.
func githubActionsToken(ctx context.Context) (token string, ok bool, err error) {
	requestToken, requestURL := os.Getenv(envGitHubRequestToken), os.Getenv(envGitHubRequestURL)
	if requestToken == "" || requestURL == "" {
		return "", false, nil
	}

	u, err := url.Parse(requestURL)
	if err != nil {
		return "", false, fmt.Errorf("parse %s: %w", envGitHubRequestURL, err)
	}

	query := u.Query()
	query.Set("audience", oidcAudience)
	u.RawQuery = query.Encode()

	//nolint:gosec // GitHub Actions sets the URL of its token service
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return "", false, err
	}

	req.Header.Set("Authorization", "bearer "+requestToken)

	resp, err := retry.DefaultClient.Do(req) //nolint:gosec // see above
	if err != nil {
		return "", false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("%w: status %s", ErrIDToken, resp.Status)
	}

	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenSize)).Decode(&body); err != nil {
		return "", false, fmt.Errorf("decode response: %w", err)
	}

	if body.Value == "" {
		return "", false, fmt.Errorf("%w: empty token", ErrIDToken)
	}

	return body.Value, true, nil
}

// googleWorkloadIdentityToken requests a token for the service account of
// the Google Compute Engine metadata server, which Cloud Build and GKE
// workload identity provide.
func googleWorkloadIdentityToken(ctx context.Context) (token string, ok bool, err error) {
	if !metadata.OnGCEWithContext(ctx) {
		return "", false, nil
	}

	query := url.Values{}
	query.Set("audience", oidcAudience)
	query.Set("format", "full")

	token, err = metadata.GetWithContext(
		ctx,
		"instance/service-accounts/default/identity?"+query.Encode(),
	)
	if err != nil || strings.TrimSpace(token) == "" {
		// Like cosign, the metadata server of an instance without a
		// service account does not count as identity.
		return "", false, nil //nolint:nilerr // not an environment with an identity
	}

	return token, true, nil
}
