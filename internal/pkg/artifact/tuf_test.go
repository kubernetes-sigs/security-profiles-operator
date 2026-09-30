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
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/stretchr/testify/require"
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

func TestTrustedMaterial(t *testing.T) {
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
