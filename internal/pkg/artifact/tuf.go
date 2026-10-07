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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

const (
	// envTUFRoot, envTUFMirror and envTUFRootJSON configure the TUF client
	// the way they configure cosign: the cache directory, the repository
	// and its trust anchor.
	envTUFRoot     = "TUF_ROOT"
	envTUFMirror   = "TUF_MIRROR"
	envTUFRootJSON = "TUF_ROOT_JSON"

	// trustedRootRefresh is how long a trusted root fetched through TUF is
	// used before it gets fetched again, the refresh period of cosign.
	trustedRootRefresh = 24 * time.Hour
)

// ErrNoCachedTrustedRoot is returned if an offline verification finds no
// usable trusted root in the TUF cache and cannot fetch one either.
var ErrNoCachedTrustedRoot = errors.New(
	"offline verification needs a trusted root file or a TUF cache populated by an earlier online verification",
)

// trustedRoots caches the trusted roots fetched through TUF, so that every
// pull does not refresh the TUF repository.
var trustedRoots = struct {
	sync.Mutex

	entries map[string]cachedTrustedRoot
}{entries: map[string]cachedTrustedRoot{}}

type cachedTrustedRoot struct {
	root    *root.TrustedRoot
	fetched time.Time
}

// tufTrustedRoot returns the trusted root of the TUF repository. Offline uses
// the TUF metadata cached on disk as long as it has not expired.
func tufTrustedRoot(offline bool) (root.TrustedMaterial, error) {
	opts, err := tufOptions()
	if err != nil {
		return nil, err
	}

	opts.ForceCache = offline
	// The trust anchor is part of the key, as it may come from TUF_ROOT_JSON.
	key := strings.Join([]string{
		opts.CachePath, opts.RepositoryBaseURL, strconv.FormatBool(offline), string(opts.Root),
	}, "\x00")

	trustedRoots.Lock()
	defer trustedRoots.Unlock()

	if cached, ok := trustedRoots.entries[key]; ok &&
		time.Since(cached.fetched) < trustedRootRefresh {
		return cached.root, nil
	}

	trustedRoot, err := root.FetchTrustedRootWithOptions(opts)
	if err != nil {
		// The TUF client falls back to an online refresh if the cache is
		// empty, which fails in an offline environment.
		if offline {
			return nil, fmt.Errorf(
				"%w, the TUF cache in %s is empty or unusable: %w",
				ErrNoCachedTrustedRoot,
				opts.CachePath,
				err,
			)
		}

		return nil, fmt.Errorf("fetch trusted root from %s: %w", opts.RepositoryBaseURL, err)
	}

	trustedRoots.entries[key] = cachedTrustedRoot{root: trustedRoot, fetched: time.Now()}

	return trustedRoot, nil
}

// tufOptions returns the options of the TUF client the way cosign sets them:
// the cache directory from TUF_ROOT, the mirror from TUF_MIRROR or from the
// remote.json of `cosign initialize`, and for any mirror but the public one
// the trust anchor from TUF_ROOT_JSON or from the cache.
func tufOptions() (*tuf.Options, error) {
	opts := tuf.DefaultOptions()

	if cachePath := os.Getenv(envTUFRoot); cachePath != "" {
		opts.CachePath = cachePath
	}

	mirror, err := tufMirror(opts.CachePath)
	if err != nil {
		return nil, err
	}

	if mirror == "" || mirror == tuf.DefaultMirror {
		return opts, nil
	}

	opts.RepositoryBaseURL = mirror

	rootJSON := os.Getenv(envTUFRootJSON)
	if rootJSON == "" {
		rootJSON = filepath.Join(opts.CachePath, tuf.URLToPath(mirror), "root.json")
	}

	opts.Root, err = os.ReadFile(rootJSON) //nolint:gosec // the TUF configuration of cosign
	if err != nil {
		return nil, fmt.Errorf("read TUF root of mirror %s: %w", mirror, err)
	}

	return opts, nil
}

// tufMirror returns the TUF mirror to use, or an empty string for the
// default.
func tufMirror(cachePath string) (string, error) {
	if mirror := os.Getenv(envTUFMirror); mirror != "" {
		return mirror, nil
	}

	raw, err := os.ReadFile(filepath.Join(cachePath, "remote.json")) //nolint:gosec // the TUF cache
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("read TUF remote.json: %w", err)
	}

	var remote map[string]string
	if err := json.Unmarshal(raw, &remote); err != nil {
		return "", fmt.Errorf("decode TUF remote.json: %w", err)
	}

	return remote["mirror"], nil
}
