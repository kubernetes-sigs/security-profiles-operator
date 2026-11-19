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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

func TestTUFOptions(t *testing.T) {
	cache := t.TempDir()
	t.Setenv(envTUFRoot, cache)
	t.Setenv(envTUFMirror, "")
	t.Setenv(envTUFRootJSON, "")

	opts, err := tufOptions()
	require.NoError(t, err)
	require.Equal(t, cache, opts.CachePath)
	require.Equal(t, tuf.DefaultMirror, opts.RepositoryBaseURL)
	require.Equal(t, tuf.DefaultRoot(), opts.Root)

	// A pinned trust anchor applies to the public mirror as well.
	pinnedRoot := filepath.Join(t.TempDir(), "root.json")
	require.NoError(t, os.WriteFile(pinnedRoot, []byte(`{"pinned":{}}`), 0o600))
	t.Setenv(envTUFRootJSON, pinnedRoot)

	opts, err = tufOptions()
	require.NoError(t, err)
	require.Equal(t, tuf.DefaultMirror, opts.RepositoryBaseURL)
	require.JSONEq(t, `{"pinned":{}}`, string(opts.Root))

	t.Setenv(envTUFRootJSON, "")

	// A mirror needs its own trust anchor.
	const mirror = "https://tuf.example.com"

	t.Setenv(envTUFMirror, mirror)

	_, err = tufOptions()
	require.ErrorContains(t, err, mirror)

	rootJSON := filepath.Join(t.TempDir(), "root.json")
	require.NoError(t, os.WriteFile(rootJSON, []byte(`{"signed":{}}`), 0o600))
	t.Setenv(envTUFRootJSON, rootJSON)

	opts, err = tufOptions()
	require.NoError(t, err)
	require.Equal(t, mirror, opts.RepositoryBaseURL)
	require.JSONEq(t, `{"signed":{}}`, string(opts.Root))

	// The mirror and the root of `cosign initialize`.
	t.Setenv(envTUFMirror, "")
	t.Setenv(envTUFRootJSON, "")
	require.NoError(t, os.WriteFile(
		filepath.Join(cache, "remote.json"), []byte(`{"mirror":"`+mirror+`"}`), 0o600,
	))
	require.NoError(t, os.MkdirAll(filepath.Join(cache, tuf.URLToPath(mirror)), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(cache, tuf.URLToPath(mirror), "root.json"), []byte(`{"cached":{}}`), 0o600,
	))

	opts, err = tufOptions()
	require.NoError(t, err)
	require.Equal(t, mirror, opts.RepositoryBaseURL)
	require.JSONEq(t, `{"cached":{}}`, string(opts.Root))

	require.NoError(t, os.WriteFile(filepath.Join(cache, "remote.json"), []byte(`{`), 0o600))

	_, err = tufOptions()
	require.ErrorContains(t, err, "remote.json")
}

// fastTUFRetries has the TUF requests retry without waiting until the test
// ends. The tests which call it are not parallel, they set the TUF
// environment.
func fastTUFRetries(t *testing.T) {
	t.Helper()

	waitMin, waitMax := tufRetryWaitMin, tufRetryWaitMax
	tufRetryWaitMin, tufRetryWaitMax = time.Millisecond, time.Millisecond

	t.Cleanup(func() { tufRetryWaitMin, tufRetryWaitMax = waitMin, waitMax })
}

func TestTrustedMaterial(t *testing.T) {
	fastTUFRetries(t)

	sigstore := newTestSigstore(t)

	material, err := (&defaultImpl{}).TrustedMaterial(t.Context(), sigstore.trustedRootPath, false)
	require.NoError(t, err)
	require.Len(t, material.FulcioCertificateAuthorities(), 2)

	_, err = (&defaultImpl{}).TrustedMaterial(
		t.Context(),
		filepath.Join(t.TempDir(), "missing.json"),
		false,
	)
	require.ErrorIs(t, err, os.ErrNotExist)

	// Offline with an empty cache and an unreachable mirror fails instead
	// of verifying without a trusted root.
	cache := t.TempDir()
	rootJSON := filepath.Join(t.TempDir(), "root.json")
	require.NoError(t, os.WriteFile(rootJSON, tuf.DefaultRoot(), 0o600))
	t.Setenv(envTUFRoot, cache)
	t.Setenv(envTUFMirror, "http://127.0.0.1:1")
	t.Setenv(envTUFRootJSON, rootJSON)

	_, err = (&defaultImpl{}).TrustedMaterial(t.Context(), "", true)
	require.ErrorIs(t, err, ErrNoCachedTrustedRoot)
	require.ErrorContains(t, err, cache)

	// Online, the error tells about the mirror instead.
	_, err = (&defaultImpl{}).TrustedMaterial(t.Context(), "", false)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNoCachedTrustedRoot)
}

func TestTUFOptionsRetry(t *testing.T) {
	fastTUFRetries(t)
	t.Setenv(envTUFRoot, t.TempDir())
	t.Setenv(envTUFMirror, "")
	t.Setenv(envTUFRootJSON, "")

	var requests atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		if _, err := w.Write([]byte("metadata")); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)

	opts, err := tufOptions()
	require.NoError(t, err)

	defaultFetcher, ok := opts.Fetcher.(*fetcher.DefaultFetcher)
	require.True(t, ok)

	// A transient error of the TUF repository gets retried instead of failing
	// the verification.
	data, err := defaultFetcher.DownloadFile(server.URL, 1024, 0)
	require.NoError(t, err)
	require.Equal(t, "metadata", string(data))
	require.Equal(t, int32(2), requests.Load())
}

// TestTUFOptionsRetryStalled asserts that an attempt whose response headers do
// not come within tufAttemptTimeout gets retried.
func TestTUFOptionsRetryStalled(t *testing.T) {
	fastTUFRetries(t)

	attemptTimeout := tufAttemptTimeout
	tufAttemptTimeout = time.Second

	t.Cleanup(func() { tufAttemptTimeout = attemptTimeout })

	t.Setenv(envTUFRoot, t.TempDir())
	t.Setenv(envTUFMirror, "")
	t.Setenv(envTUFRootJSON, "")

	var requests atomic.Int32

	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			<-release

			return
		}

		if _, err := w.Write([]byte("metadata")); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	opts, err := tufOptions()
	require.NoError(t, err)

	defaultFetcher, ok := opts.Fetcher.(*fetcher.DefaultFetcher)
	require.True(t, ok)

	data, err := defaultFetcher.DownloadFile(server.URL, 1024, 0)
	require.NoError(t, err)
	require.Equal(t, "metadata", string(data))
	// A slow runner may stall the second attempt as well.
	require.GreaterOrEqual(t, requests.Load(), int32(2))
}

// TestTrustedMaterialCanceled asserts that a caller stops waiting for a TUF
// refresh once its context ends, also if the mirror never answers.
func TestTrustedMaterialCanceled(t *testing.T) {
	fastTUFRetries(t)

	requested := make(chan struct{}, 1)
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}

		<-release
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	rootJSON := filepath.Join(t.TempDir(), "root.json")
	require.NoError(t, os.WriteFile(rootJSON, tuf.DefaultRoot(), 0o600))
	t.Setenv(envTUFRoot, t.TempDir())
	t.Setenv(envTUFMirror, server.URL)
	t.Setenv(envTUFRootJSON, rootJSON)

	// The abandoned refresh ends once the mirror answers, which the cleanup
	// waits for, so that it does not outlive the test.
	key := tufFetchKey("trusted-root/false")

	t.Cleanup(func() {
		// The abandoned refresh fails on the answer of the mirror.
		_, err, _ := tufFetches.Do(key, func() (any, error) { return struct{}{}, nil })
		t.Log("abandoned TUF refresh:", err)
	})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() {
		_, err := (&defaultImpl{}).TrustedMaterial(ctx, "", false)
		done <- err
	}()

	select {
	case <-requested:
	case <-time.After(time.Minute):
		require.Fail(t, "the TUF mirror got no request")
	}

	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Minute):
		require.Fail(t, "the caller kept waiting for the TUF mirror")
	}
}

// TestRetryStalledTUFAttempt asserts that an attempt whose response headers
// did not come in time is retried, unlike a request whose context ended.
func TestRetryStalledTUFAttempt(t *testing.T) {
	t.Parallel()

	stalled := &url.Error{
		Op:  "Get",
		URL: "https://tuf.example",
		Err: fmt.Errorf("stalled: %w", context.DeadlineExceeded),
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://tuf.example", nil)
	require.True(t, retryStalledTUFAttempt(req, nil, stalled))
	require.True(
		t,
		retryStalledTUFAttempt(req, &http.Response{StatusCode: http.StatusBadGateway}, nil),
	)
	require.False(
		t,
		retryStalledTUFAttempt(req, &http.Response{StatusCode: http.StatusNotFound}, nil),
	)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	canceled := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://tuf.example", nil)
	require.False(t, retryStalledTUFAttempt(canceled, nil, stalled))
}
