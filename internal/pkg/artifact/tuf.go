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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
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

	// tufRequestTimeout bounds every request to the TUF repository. The TUF
	// client takes no context, and the default HTTP client never times out.
	tufRequestTimeout = time.Minute
)

// ErrNoCachedTrustedRoot is returned if an offline verification finds no
// usable trusted root in the TUF cache and cannot fetch one either.
var ErrNoCachedTrustedRoot = errors.New(
	"offline verification needs a trusted root file or a TUF cache populated by an earlier online verification",
)

// tufCache caches what gets read through TUF for trustedRootRefresh, so that
// every pull or push does not refresh the TUF repository.
type tufCache[T any] struct {
	sync.Mutex

	entries map[string]tufCacheEntry[T]
}

type tufCacheEntry[T any] struct {
	value   T
	fetched time.Time
}

// get returns the cached value for the key, or fetches and caches it.
func (c *tufCache[T]) get(key string, fetch func() (T, error)) (T, error) {
	c.Lock()
	defer c.Unlock()

	if cached, ok := c.entries[key]; ok && time.Since(cached.fetched) < trustedRootRefresh {
		return cached.value, nil
	}

	value, err := fetch()
	if err != nil {
		return value, err
	}

	c.entries[key] = tufCacheEntry[T]{value: value, fetched: time.Now()}

	return value, nil
}

var (
	// tufClients holds the TUF clients, which refresh the metadata of the
	// repository when they get created. Signing reads the trusted root and
	// the signing config through the same client, so it refreshes once.
	// The updater of a client is not safe for concurrent use, the lock of
	// the cache is held while a client reads a target, see tufTarget.
	tufClients = tufCache[*tuf.Client]{
		entries: map[string]tufCacheEntry[*tuf.Client]{},
	}
	trustedRoots = tufCache[*root.TrustedRoot]{
		entries: map[string]tufCacheEntry[*root.TrustedRoot]{},
	}
)

// tufCacheKey identifies a TUF repository and how it gets read. The trust
// anchor is part of the key, as it may come from TUF_ROOT_JSON.
func tufCacheKey(opts *tuf.Options, offline bool) string {
	return strings.Join([]string{
		opts.CachePath, opts.RepositoryBaseURL, strconv.FormatBool(offline), string(opts.Root),
	}, "\x00")
}

// tufTrustedRoot returns the trusted root of the TUF repository. Offline uses
// the TUF metadata cached on disk as long as it has not expired.
func tufTrustedRoot(offline bool) (root.TrustedMaterial, error) {
	opts, err := tufOptions()
	if err != nil {
		return nil, err
	}

	opts.ForceCache = offline
	key := tufCacheKey(opts, offline)

	return trustedRoots.get(key, func() (*root.TrustedRoot, error) {
		trustedRoot, err := tufTarget(opts, key, root.GetTrustedRoot)
		if err == nil {
			return trustedRoot, nil
		}

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
	})
}

// tufSigningConfig returns the signing config of the TUF repository. It uses
// the client which got the trusted root, so that signing refreshes the
// repository once.
func tufSigningConfig() (*root.SigningConfig, error) {
	opts, err := tufOptions()
	if err != nil {
		return nil, err
	}

	signingConfig, err := tufTarget(opts, tufCacheKey(opts, false), root.GetSigningConfig)
	if err != nil {
		return nil, fmt.Errorf("fetch signing config from %s: %w", opts.RepositoryBaseURL, err)
	}

	return signingConfig, nil
}

// tufTarget reads a target of the TUF repository with the cached client of
// the key, which gets created with the options if there is none. A client
// gets cached once it read a target, a failed read refreshes the repository
// again the next time instead of using the metadata of the failed one.
func tufTarget[T any](opts *tuf.Options, key string, get func(*tuf.Client) (T, error)) (T, error) {
	var zero T

	tufClients.Lock()
	defer tufClients.Unlock()

	client := (*tuf.Client)(nil)
	if cached, ok := tufClients.entries[key]; ok &&
		time.Since(cached.fetched) < trustedRootRefresh {
		client = cached.value
	}

	fetched := client == nil
	if fetched {
		var err error

		client, err = tuf.New(opts)
		if err != nil {
			return zero, fmt.Errorf("create TUF client: %w", err)
		}
	}

	value, err := get(client)
	if err != nil {
		delete(tufClients.entries, key)

		return zero, err
	}

	if fetched {
		tufClients.entries[key] = tufCacheEntry[*tuf.Client]{value: client, fetched: time.Now()}
	}

	return value, nil
}

// tufOptions returns the options of the TUF client the way cosign sets them:
// the cache directory from TUF_ROOT, the mirror from TUF_MIRROR or from the
// remote.json of `cosign initialize`, and the trust anchor from TUF_ROOT_JSON,
// which any mirror but the public one needs, from the cache otherwise.
func tufOptions() (*tuf.Options, error) {
	opts := tuf.DefaultOptions()

	if defaultFetcher, ok := opts.Fetcher.(*fetcher.DefaultFetcher); ok {
		defaultFetcher.SetHTTPClient(&http.Client{Timeout: tufRequestTimeout})
	}

	if cachePath := os.Getenv(envTUFRoot); cachePath != "" {
		opts.CachePath = cachePath
	}

	mirror, err := tufMirror(opts.CachePath)
	if err != nil {
		return nil, err
	}

	rootJSON := os.Getenv(envTUFRootJSON)

	if mirror == "" || mirror == tuf.DefaultMirror {
		// The public mirror has its root embedded, unless one is pinned.
		if rootJSON == "" {
			return opts, nil
		}

		mirror = tuf.DefaultMirror
	}

	opts.RepositoryBaseURL = mirror

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
