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
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

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

	// The transport of the server is its own, because closing a server also
	// closes the idle connections of http.DefaultTransport, which breaks the
	// requests of parallel tests.
	return &http.Client{
		Transport: &rewriteHostTransport{host: target.Host, base: server.Client().Transport},
	}
}

type rewriteHostTransport struct {
	host string
	base http.RoundTripper
}

func (t *rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	req.URL.Host = t.host

	return t.base.RoundTrip(req)
}

func TestIsSelinuxdReady(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		body      string
		want      bool
		wantError bool
	}{
		"ready":                    {body: `{"ready": true}`, want: true},
		"not ready":                {body: `{"ready": false}`, want: false},
		"missing key is not ready": {body: `{}`, want: false},
		"malformed response":       {body: `not json`, wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := func(w http.ResponseWriter, _ *http.Request) {
				writeBody(t, w, tc.body)
			}

			got, err := isSelinuxdReady(context.Background(), selinuxdTestClient(t, handler))
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
