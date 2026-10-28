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

package signing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
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
	require.ErrorIs(t, err, artifact.ErrIDToken)
}

func TestFileToken(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for _, tc := range []struct {
		name      string
		content   *string
		wantToken string
	}{
		{name: "missing"},
		{name: "present", content: new("file-token"), wantToken: "file-token"},
		{name: "trailing newline", content: new("file-token\n"), wantToken: "file-token"},
		{name: "empty", content: new("")},
		{name: "whitespace only", content: new(" \n\t")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(dir, tc.name)
			if tc.content != nil {
				require.NoError(t, os.WriteFile(path, []byte(*tc.content), 0o600))
			}

			token, ok, err := fileToken(path)
			require.NoError(t, err)
			require.Equal(t, tc.wantToken != "", ok)
			require.Equal(t, tc.wantToken, token)
		})
	}

	t.Run("unreadable", func(t *testing.T) {
		t.Parallel()

		// A directory exists but cannot be read as a file.
		_, ok, err := fileToken(dir)
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("no permission", func(t *testing.T) {
		t.Parallel()

		if os.Geteuid() == 0 {
			t.Skip("root reads the files anyway")
		}

		// A file which cannot be read is an error, the sign in must not
		// fall back to another identity.
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte("file-token"), 0o000))

		_, ok, err := fileToken(path)
		require.ErrorIs(t, err, os.ErrPermission)
		require.False(t, ok)

		// A directory which cannot be read hides the file, like a missing
		// one.
		hidden := t.TempDir()
		require.NoError(
			t,
			os.WriteFile(filepath.Join(hidden, "token"), []byte("file-token"), 0o600),
		)
		require.NoError(t, os.Chmod(hidden, 0o000))
		t.Cleanup(func() { require.NoError(t, os.Chmod(hidden, 0o700)) })

		token, ok, err := fileToken(filepath.Join(hidden, "token"))
		require.NoError(t, err)
		require.False(t, ok)
		require.Empty(t, token)
	})
}

func TestIDTokenAmbient(t *testing.T) {
	t.Setenv(envGitHubRequestToken, "")
	t.Setenv(envGitHubRequestURL, "")
	t.Setenv(envSigstoreIDToken, "env-token")

	token, err := idToken(t.Context(), "https://oauth2.example.com", false)
	require.NoError(t, err)
	require.Equal(t, "env-token", token)

	// A provider which fails does not stop the next one.
	t.Setenv(envGitHubRequestToken, "request-token")
	t.Setenv(envGitHubRequestURL, githubTokenServer(t, http.StatusInternalServerError))

	token, err = idToken(t.Context(), "https://oauth2.example.com", false)
	require.NoError(t, err)
	require.Equal(t, "env-token", token)

	// GitHub Actions comes first.
	t.Setenv(envGitHubRequestURL, githubTokenServer(t, http.StatusOK))

	token, err = idToken(t.Context(), "https://oauth2.example.com", false)
	require.NoError(t, err)
	require.Equal(t, "github-token", token)
}

// TestIDTokenWithoutIssuer asserts that a signing config without OIDC
// provider signs with a token of the environment, and fails without one
// instead of signing in nowhere.
func TestIDTokenWithoutIssuer(t *testing.T) {
	t.Setenv(envGitHubRequestToken, "")
	t.Setenv(envGitHubRequestURL, "")
	t.Setenv(envSigstoreIDToken, "env-token")

	token, err := idToken(t.Context(), "", false)
	require.NoError(t, err)
	require.Equal(t, "env-token", token)

	t.Setenv(envSigstoreIDToken, "")

	_, err = idToken(t.Context(), "", true)
	require.ErrorIs(t, err, artifact.ErrNoOIDCProvider)
}

func TestEnvToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		ok    bool
	}{
		{name: "set", value: "env-token", ok: true},
		{name: "empty", value: ""},
		{name: "blank", value: " \n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envSigstoreIDToken, tc.value)

			token, ok, err := envToken(t.Context())
			require.NoError(t, err)
			require.Equal(t, tc.ok, ok)

			if tc.ok {
				require.Equal(t, tc.value, token)
			}
		})
	}
}

func TestTokenGetter(t *testing.T) {
	t.Parallel()

	const issuer = "https://oauth2.example.com"

	errProvider := errors.New("provider failed")

	none := tokenProvider{
		name:    "none",
		provide: func(context.Context) (string, bool, error) { return "", false, nil },
	}
	ambient := tokenProvider{
		name:    "ambient",
		provide: func(context.Context) (string, bool, error) { return "ambient-token", true, nil },
	}
	failing := tokenProvider{
		name:    "failing",
		provide: func(context.Context) (string, bool, error) { return "", false, errProvider },
	}

	for _, tc := range []struct {
		name            string
		providers       []tokenProvider
		deviceFlow      bool
		terminal        bool
		wantToken       string
		wantInteractive bool
		wantErr         error
	}{
		{
			name:      "ambient token",
			providers: []tokenProvider{none, ambient},
			wantToken: "ambient-token",
		},
		{
			name:      "failing provider without token",
			providers: []tokenProvider{failing, none},
			terminal:  true,
			wantErr:   errProvider,
		},
		{
			name:            "terminal",
			providers:       []tokenProvider{none},
			terminal:        true,
			wantInteractive: true,
		},
		{
			name:            "device flow without terminal",
			providers:       []tokenProvider{none},
			deviceFlow:      true,
			wantInteractive: true,
		},
		{
			name:      "no terminal and no device flow",
			providers: []tokenProvider{none},
			wantErr:   artifact.ErrNoInteractiveSignIn,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			source, err := tokenGetter(
				t.Context(),
				tc.providers,
				issuer,
				tc.deviceFlow,
				tc.terminal,
			)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, source)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantToken, source.token)
			require.Equal(t, tc.wantInteractive, source.interactive != nil)
		})
	}
}
