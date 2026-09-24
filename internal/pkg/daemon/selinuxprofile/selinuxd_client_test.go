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

package selinuxprofile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// writeFileIfDiffers decides whether a policy file on the node gets rewritten,
// which in turn decides whether selinuxd reloads the policy.
func TestWriteFileIfDiffers(t *testing.T) {
	t.Parallel()

	t.Run("writes a file that does not exist", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")

		written, err := writeFileIfDiffers(path, []byte("content"), logr.Discard())
		require.NoError(t, err)
		require.True(t, written)

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "content", string(got))
	})

	t.Run("does not rewrite identical content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

		written, err := writeFileIfDiffers(path, []byte("content"), logr.Discard())
		require.NoError(t, err)
		require.False(t, written, "an unchanged policy must not trigger a reload")
	})

	t.Run("rewrites changed content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))

		written, err := writeFileIfDiffers(path, []byte("new"), logr.Discard())
		require.NoError(t, err)
		require.True(t, written)

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "new", string(got))
	})

	t.Run("an empty file differs from content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, nil, 0o600))

		written, err := writeFileIfDiffers(path, []byte("content"), logr.Discard())
		require.NoError(t, err)
		require.True(t, written)
	})

	t.Run("fails when the path is not readable", func(t *testing.T) {
		t.Parallel()

		// A directory cannot be read as a policy file.
		dir := t.TempDir()

		_, err := writeFileIfDiffers(dir, []byte("content"), logr.Discard())
		require.Error(t, err)
	})
}

// writeBody writes a canned selinuxd response, failing the test if it cannot.
// Assertions cannot run inside the handler goroutine, so this records the error
// and lets the request fail instead.
func writeBody(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()

	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("writing test response: %v", err)
	}
}

// selinuxdTestClient routes the fixed selinuxd URLs at a test server.
func selinuxdTestClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	target, err := url.Parse(server.URL)
	require.NoError(t, err)

	return &http.Client{
		Transport: &rewriteHostTransport{host: target.Host},
	}
}

type rewriteHostTransport struct {
	host string
}

func (t *rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = t.host

	return http.DefaultTransport.RoundTrip(req)
}

func TestIsSelinuxdReady(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		handler   http.HandlerFunc
		want      bool
		wantError bool
	}{
		"ready": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `{"ready": true}`)
			},
			want: true,
		},
		"not ready": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `{"ready": false}`)
			},
			want: false,
		},
		"missing key is not ready": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `{}`)
			},
			want: false,
		},
		"malformed response": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `not json`)
			},
			wantError: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := isSelinuxdReady(context.Background(), selinuxdTestClient(t, tc.handler))
			if tc.wantError {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGetPolicyStatus(t *testing.T) {
	t.Parallel()

	profile := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-policy"},
	}

	t.Run("installed", func(t *testing.T) {
		t.Parallel()

		var gotPath string

		status, err := getPolicyStatus(context.Background(), profile,
			selinuxdTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path

				writeBody(t, w, `{"status": "Installed", "msg": "ok"}`)
			}))
		require.NoError(t, err)
		require.Equal(t, installedStatus, status.Status)
		require.Contains(t, gotPath, "test-policy",
			"the policy name must reach selinuxd")
	})

	t.Run("failed", func(t *testing.T) {
		t.Parallel()

		status, err := getPolicyStatus(context.Background(), profile,
			selinuxdTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `{"status": "Failed", "msg": "boom"}`)
			}))
		require.NoError(t, err)
		require.Equal(t, failedStatus, status.Status)
		require.Equal(t, "boom", status.Msg)
	})

	t.Run("not found is reported as such", func(t *testing.T) {
		t.Parallel()

		_, err := getPolicyStatus(context.Background(), profile,
			selinuxdTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
		require.ErrorIs(t, err, errPolicyNotFound)
	})

	t.Run("other HTTP errors are surfaced", func(t *testing.T) {
		t.Parallel()

		_, err := getPolicyStatus(context.Background(), profile,
			selinuxdTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
		require.ErrorContains(t, err, "500")
	})

	t.Run("an unknown status value is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := getPolicyStatus(context.Background(), profile,
			selinuxdTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `{"status": "Something"}`)
			}))
		require.ErrorContains(t, err, "invalid sePolStatus")
	})

	t.Run("a malformed body is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := getPolicyStatus(context.Background(), profile,
			selinuxdTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, `not json`)
			}))
		require.ErrorContains(t, err, "failed to decode")
	})
}
