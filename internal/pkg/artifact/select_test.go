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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/errdef"
)

func platformLayer(platform *ocispec.Platform) ocispec.Descriptor {
	layer := testLayer(profileName(platform))
	layer.Platform = platform

	return layer
}

func TestSelectLayer(t *testing.T) {
	t.Parallel()

	amd64 := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := &ocispec.Platform{OS: "linux", Architecture: "arm64"}
	arm64v8 := &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	neutral := testLayer(defaultProfileYAML)

	manyLayers := make([]ocispec.Descriptor, maxArtifactLayers+1)
	for i := range manyLayers {
		manyLayers[i] = testLayer(strconv.Itoa(i))
	}

	for _, tc := range []struct {
		name     string
		manifest *ocispec.Manifest
		platform *ocispec.Platform
		want     ocispec.Descriptor
		wantErr  error
	}{
		{
			name:     "layer of the platform",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(amd64), platformLayer(arm64)}},
			platform: arm64,
			want:     platformLayer(arm64),
		},
		{
			name:     "default arm64 variant is normalized on pull",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(amd64), platformLayer(arm64)}},
			platform: arm64v8,
			want:     platformLayer(arm64),
		},
		{
			name:     "default arm64 variant is normalized on push",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(arm64v8)}},
			platform: arm64,
			want:     platformLayer(arm64v8),
		},
		{
			name:     "platform independent layer serves every platform",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{neutral}},
			platform: arm64,
			want:     neutral,
		},
		{
			name:     "platform independent layer as fallback",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(amd64), neutral}},
			platform: arm64,
			want:     neutral,
		},
		{
			name:     "platform independent layer without platform",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(amd64), neutral}},
			want:     neutral,
		},
		{
			name:     "single layer of another platform",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(amd64)}},
			platform: arm64,
			wantErr:  ErrPlatformMismatch,
		},
		{
			name:     "no layer of the platform",
			manifest: &ocispec.Manifest{Layers: []ocispec.Descriptor{platformLayer(amd64), platformLayer(arm64v8)}},
			platform: &ocispec.Platform{OS: "linux", Architecture: "s390x"},
			wantErr:  ErrNoSingleLayer,
		},
		{
			name:     "too many layers",
			manifest: &ocispec.Manifest{Layers: manyLayers},
			platform: amd64,
			wantErr:  ErrTooManyLayers,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			layer, runtimeFormat, err := selectLayer(tc.manifest, tc.platform)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.False(t, runtimeFormat)
			require.Equal(t, tc.want, *layer)
		})
	}
}

// memoryStorage is a content.ReadOnlyStorage which serves blobs from memory.
type memoryStorage map[digest.Digest][]byte

//nolint:gocritic // the signature is defined by content.Fetcher
func (m memoryStorage) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	blob, ok := m[desc.Digest]
	if !ok {
		return nil, errdef.ErrNotFound
	}

	return io.NopCloser(bytes.NewReader(blob)), nil
}

//nolint:gocritic // the signature is defined by content.ReadOnlyStorage
func (m memoryStorage) Exists(_ context.Context, desc ocispec.Descriptor) (bool, error) {
	_, ok := m[desc.Digest]

	return ok, nil
}

// add stores the JSON encoding of v and returns its descriptor.
func (m memoryStorage) add(t *testing.T, mediaType string, v any) ocispec.Descriptor {
	t.Helper()

	blob, err := json.Marshal(v)
	require.NoError(t, err)

	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(blob),
		Size:      int64(len(blob)),
	}
	m[desc.Digest] = blob

	return desc
}

func TestSelectManifest(t *testing.T) {
	t.Parallel()

	amd64 := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	arm64v8 := &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}

	storage := memoryStorage{}
	amd64Manifest := storage.add(t, ocispec.MediaTypeImageManifest, &ocispec.Manifest{})
	amd64Manifest.Platform = amd64
	arm64Manifest := storage.add(t, ocispec.MediaTypeImageManifest, &ocispec.Manifest{
		Annotations: map[string]string{"arch": "arm64"},
	})
	arm64Manifest.Platform = arm64v8
	neutralManifest := storage.add(t, ocispec.MediaTypeImageManifest, &ocispec.Manifest{
		Annotations: map[string]string{"arch": "none"},
	})

	multiPlatform := storage.add(t, ocispec.MediaTypeImageIndex, &ocispec.Index{
		Manifests: []ocispec.Descriptor{amd64Manifest, arm64Manifest},
	})
	singleNeutral := storage.add(t, ocispec.MediaTypeImageIndex, &ocispec.Index{
		Manifests: []ocispec.Descriptor{neutralManifest},
	})
	dockerList := multiPlatform
	dockerList.MediaType = mediaTypeDockerManifestList

	for _, tc := range []struct {
		name     string
		root     ocispec.Descriptor
		platform *ocispec.Platform
		limit    int64
		want     ocispec.Descriptor
		wantErr  error
	}{
		{
			name:     "manifest stays the root",
			root:     neutralManifest,
			platform: amd64,
			want:     neutralManifest,
		},
		{
			name:     "index resolves to the manifest of the platform",
			root:     multiPlatform,
			platform: amd64,
			want:     amd64Manifest,
		},
		{
			name:     "docker manifest list resolves to the manifest of the platform",
			root:     dockerList,
			platform: &ocispec.Platform{OS: "linux", Architecture: "arm64"},
			want:     arm64Manifest,
		},
		{
			name:     "index with a single manifest without platform",
			root:     singleNeutral,
			platform: amd64,
			want:     neutralManifest,
		},
		{
			name:     "index without a manifest for the platform",
			root:     multiPlatform,
			platform: &ocispec.Platform{OS: "linux", Architecture: "s390x"},
			wantErr:  ErrNoMatchingManifest,
		},
		{
			name:     "index above the size limit",
			root:     multiPlatform,
			platform: amd64,
			limit:    1,
			wantErr:  ErrBlobTooLarge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			limit := tc.limit
			if limit == 0 {
				limit = DefaultMaxBlobSize
			}

			got, err := selectManifest(tc.platform, limit)(t.Context(), storage, tc.root)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestProfileLayer verifies that a pull copies only the profile layer for the
// platform, no matter how many layers the artifact has.
func TestProfileLayer(t *testing.T) {
	t.Parallel()

	amd64 := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := &ocispec.Platform{OS: "linux", Architecture: "arm64"}

	storage := memoryStorage{}
	subject := storage.add(t, ocispec.MediaTypeImageManifest, &ocispec.Manifest{})

	const otherLayers = 10

	layers := make([]ocispec.Descriptor, 0, 2+otherLayers)
	layers = append(layers, platformLayer(amd64), platformLayer(arm64))

	for i := range otherLayers {
		layers = append(layers, testLayer("other-"+strconv.Itoa(i)))
	}

	manifest := storage.add(t, ocispec.MediaTypeImageManifest, &ocispec.Manifest{
		Config:  ocispec.DescriptorEmptyJSON,
		Layers:  layers,
		Subject: &subject,
	})

	successors, err := profileLayer(arm64)(t.Context(), storage, manifest)
	require.NoError(t, err)
	require.Equal(t, []ocispec.Descriptor{platformLayer(arm64)}, successors)

	successors, err = profileLayer(arm64)(t.Context(), storage, platformLayer(arm64))
	require.NoError(t, err)
	require.Empty(t, successors)

	index := storage.add(t, ocispec.MediaTypeImageIndex, &ocispec.Index{})
	_, err = profileLayer(arm64)(t.Context(), storage, index)
	require.ErrorIs(t, err, ErrNoMatchingManifest)

	tooMany := storage.add(t, ocispec.MediaTypeImageManifest, &ocispec.Manifest{
		Layers: make([]ocispec.Descriptor, maxArtifactLayers+1),
	})
	_, err = profileLayer(arm64)(t.Context(), storage, tooMany)
	require.ErrorIs(t, err, ErrTooManyLayers)
}

// TestFileStoreSkipsUnpack verifies that a layer annotated for unpacking is
// stored as it is instead of extracted without any size limit.
func TestFileStoreSkipsUnpack(t *testing.T) {
	t.Parallel()

	var archive bytes.Buffer

	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	content := []byte("unpacked")
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{
		Name: "dir/file", Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg,
	}))
	_, err := tarWriter.Write(content)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())

	dir := t.TempDir()
	store, err := (&defaultImpl{}).FileNew(dir)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, store.Close()) })

	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(archive.Bytes()),
		Size:      int64(archive.Len()),
		Annotations: map[string]string{
			ocispec.AnnotationTitle: "dir",
			file.AnnotationUnpack:   "true",
		},
	}
	require.NoError(t, store.Push(t.Context(), desc, bytes.NewReader(archive.Bytes())))

	info, err := os.Stat(filepath.Join(dir, "dir"))
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular(), "layer got unpacked")
}

// TestKeychainCredential verifies that registry access without username and
// password uses the docker config, like cosign does for the signatures.
func TestKeychainCredential(t *testing.T) {
	home := t.TempDir()
	dockerConfig := filepath.Join(home, ".docker")
	require.NoError(t, os.MkdirAll(dockerConfig, 0o700))

	basic := func(user, password string) string {
		return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
	}

	config, err := json.Marshal(map[string]any{"auths": map[string]any{
		"registry.example.com":        map[string]string{"auth": basic("user", "pass")},
		"https://index.docker.io/v1/": map[string]string{"auth": basic("hub", "secret")},
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dockerConfig, "config.json"), config, 0o600))

	t.Setenv("HOME", home)
	t.Setenv("DOCKER_CONFIG", dockerConfig)

	credential, err := keychainCredential(t.Context(), "registry.example.com")
	require.NoError(t, err)
	require.Equal(t, "user", credential.Username)
	require.Equal(t, "pass", credential.Password)

	credential, err = keychainCredential(t.Context(), dockerHubRegistryHost)
	require.NoError(t, err)
	require.Equal(t, "hub", credential.Username)
	require.Equal(t, "secret", credential.Password)

	credential, err = keychainCredential(t.Context(), "other.example.com")
	require.NoError(t, err)
	require.Empty(t, credential.Username)
	require.Empty(t, credential.Password)
}
