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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// githubTokenServer serves identity tokens like GitHub Actions.
func githubTokenServer(t *testing.T, status int) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer request-token" ||
			r.URL.Query().Get("audience") != oidcAudience ||
			r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		w.WriteHeader(status)

		if _, err := w.Write([]byte(`{"value":"github-token"}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	return server.URL + "/token?api-version=2.0"
}

func TestGitHubActionsToken(t *testing.T) {
	t.Setenv(envGitHubRequestToken, "")
	t.Setenv(envGitHubRequestURL, "")

	_, ok, err := githubActionsToken(t.Context())
	require.NoError(t, err)
	require.False(t, ok)

	t.Setenv(envGitHubRequestToken, "request-token")
	t.Setenv(envGitHubRequestURL, githubTokenServer(t, http.StatusOK))

	token, ok, err := githubActionsToken(t.Context())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "github-token", token)

	t.Setenv(envGitHubRequestToken, "wrong-token")

	_, _, err = githubActionsToken(t.Context())
	require.ErrorIs(t, err, ErrIDToken)
}

func TestIDTokenAmbient(t *testing.T) {
	t.Setenv(envGitHubRequestToken, "")
	t.Setenv(envGitHubRequestURL, "")
	t.Setenv(envSigstoreIDToken, "env-token")

	token, err := idToken(t.Context(), "https://oauth2.example.com")
	require.NoError(t, err)
	require.Equal(t, "env-token", token)

	// A provider which fails does not stop the next one.
	t.Setenv(envGitHubRequestToken, "request-token")
	t.Setenv(envGitHubRequestURL, githubTokenServer(t, http.StatusInternalServerError))

	token, err = idToken(t.Context(), "https://oauth2.example.com")
	require.NoError(t, err)
	require.Equal(t, "env-token", token)

	// GitHub Actions comes first.
	t.Setenv(envGitHubRequestURL, githubTokenServer(t, http.StatusOK))

	token, err = idToken(t.Context(), "https://oauth2.example.com")
	require.NoError(t, err)
	require.Equal(t, "github-token", token)
}
