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
	"fmt"
	"sync"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	orascontent "oras.land/oras-go/v2/content"
)

// selectLayer returns the layer of the manifest holding the profile for the
// platform, together with whether the artifact uses the KEP-6061 runtime
// format. It prefers the layers push produces: the one bound to the platform,
// then the platform independent one. As fallback, it takes the single layer
// of the artifact because KEP-6061 mandates no particular layer name, unless
// that layer is bound to another platform.
func selectLayer(manifest *v1.Manifest, platform *v1.Platform) (*v1.Descriptor, bool, error) {
	if len(manifest.Layers) > maxArtifactLayers {
		return nil, false, fmt.Errorf(
			"%w: got %d, limit is %d", ErrTooManyLayers, len(manifest.Layers), maxArtifactLayers,
		)
	}

	// KEP-6061 identifies the artifact by the config media type, with the
	// artifact type as fallback for the empty OCI config descriptor.
	if manifest.Config.MediaType == MediaTypeSeccompProfile ||
		manifest.ArtifactType == MediaTypeSeccompProfile {
		if len(manifest.Layers) != 1 {
			return nil, false, fmt.Errorf("%w: got %d", ErrNoSingleLayer, len(manifest.Layers))
		}

		return &manifest.Layers[0], true, nil
	}

	if platform != nil {
		name := profileName(platform)

		for i := range manifest.Layers {
			layer := &manifest.Layers[i]

			if layer.Platform != nil && platformMatches(layer.Platform, platform) {
				return layer, false, nil
			}

			if layer.Platform == nil && layer.Annotations[v1.AnnotationTitle] == name {
				return layer, false, nil
			}
		}
	}

	for _, name := range []string{defaultProfileYAML, defaultProfileJSON} {
		for i := range manifest.Layers {
			layer := &manifest.Layers[i]

			if layer.Platform == nil && layer.Annotations[v1.AnnotationTitle] == name {
				return layer, false, nil
			}
		}
	}

	if len(manifest.Layers) != 1 {
		return nil, false, fmt.Errorf("%w: got %d", ErrNoSingleLayer, len(manifest.Layers))
	}

	layer := &manifest.Layers[0]
	if !layerMatchesPlatform(layer, platform) {
		return nil, false, fmt.Errorf(
			"%w: %s (%s)", ErrPlatformMismatch,
			layer.Annotations[v1.AnnotationTitle], platformToString(layer.Platform),
		)
	}

	return layer, false, nil
}

// layerMatchesPlatform reports whether the layer can be used for the
// requested platform. Layers without a platform are only eligible if they are
// not named for one either.
func layerMatchesPlatform(layer *v1.Descriptor, platform *v1.Platform) bool {
	if layer.Platform == nil {
		return !platformQualifiedName.MatchString(layer.Annotations[v1.AnnotationTitle])
	}

	return platform != nil && platformMatches(layer.Platform, platform)
}

// platformMatches reports whether both platforms are the same, with the
// variants normalized the way container runtimes do it, so that for example
// linux/arm64/v8 matches linux/arm64.
func platformMatches(have, want *v1.Platform) bool {
	return have.OS == want.OS &&
		have.Architecture == want.Architecture &&
		normalizeVariant(have.Architecture, have.Variant) ==
			normalizeVariant(want.Architecture, want.Variant) &&
		have.OSVersion == want.OSVersion
}

// normalizeVariant returns the variant of the architecture, with the default
// variant made explicit or omitted the way containerd normalizes it.
func normalizeVariant(architecture, variant string) string {
	switch architecture {
	case "arm64":
		if variant == "v8" {
			return ""
		}
	case "arm":
		if variant == "" {
			return "v7"
		}
	case "amd64":
		if variant == "v1" {
			return ""
		}
	}

	return variant
}

// selectManifest returns the ORAS MapRoot hook which resolves an image index
// to the manifest for the platform, which is the only one to get copied.
// Manifests are left as they are.
func selectManifest(
	platform *v1.Platform, limit int64,
) func(context.Context, orascontent.ReadOnlyStorage, v1.Descriptor) (v1.Descriptor, error) {
	return func(ctx context.Context, src orascontent.ReadOnlyStorage, root v1.Descriptor) (v1.Descriptor, error) {
		if !isIndex(root.MediaType) {
			return root, nil
		}

		if err := blobSizeLimit(limit)(ctx, root); err != nil {
			return v1.Descriptor{}, err
		}

		raw, err := orascontent.FetchAll(ctx, src, root)
		if err != nil {
			return v1.Descriptor{}, fmt.Errorf("fetch index: %w", err)
		}

		index := &v1.Index{}
		if err := json.Unmarshal(raw, index); err != nil {
			return v1.Descriptor{}, fmt.Errorf("unmarshal index: %w", err)
		}

		manifest, err := selectIndexManifest(index, platform)
		if err != nil {
			return v1.Descriptor{}, err
		}

		if isIndex(manifest.MediaType) {
			return v1.Descriptor{}, fmt.Errorf(
				"%w: nested index %s",
				ErrNoMatchingManifest,
				manifest.Digest,
			)
		}

		return *manifest, nil
	}
}

// selectIndexManifest returns the manifest of the index for the platform. An
// index with a single manifest without platform serves every platform.
func selectIndexManifest(index *v1.Index, platform *v1.Platform) (*v1.Descriptor, error) {
	if len(index.Manifests) > maxArtifactLayers {
		return nil, fmt.Errorf(
			"%w: index has %d manifests, limit is %d",
			ErrTooManyLayers, len(index.Manifests), maxArtifactLayers,
		)
	}

	if platform != nil {
		for i := range index.Manifests {
			manifest := &index.Manifests[i]
			if manifest.Platform != nil && platformMatches(manifest.Platform, platform) {
				return manifest, nil
			}
		}
	}

	if len(index.Manifests) == 1 && index.Manifests[0].Platform == nil {
		return &index.Manifests[0], nil
	}

	return nil, fmt.Errorf("%w: %s", ErrNoMatchingManifest, platformToString(platform))
}

// layerSelection selects the profile layer of the manifest a pull copies for
// the platform, and remembers it, so that reading the profile does not have
// to parse the manifest again.
type layerSelection struct {
	platform *v1.Platform

	mu            sync.Mutex
	layer         *v1.Descriptor
	runtimeFormat bool
}

// findSuccessors is the ORAS FindSuccessors hook which limits the copy of a
// manifest to the layer selectLayer picks for the platform. Everything else
// of the artifact, like the layers of other platforms, the config or a
// subject, is not needed to read the profile.
//
//nolint:gocritic // the signature of the ORAS FindSuccessors hook
func (s *layerSelection) findSuccessors(
	ctx context.Context, fetcher orascontent.Fetcher, desc v1.Descriptor,
) ([]v1.Descriptor, error) {
	switch {
	case isIndex(desc.MediaType):
		// selectManifest maps an index root to a manifest already.
		return nil, fmt.Errorf("%w: nested index %s", ErrNoMatchingManifest, desc.Digest)
	case desc.MediaType != v1.MediaTypeImageManifest && desc.MediaType != mediaTypeDockerManifest:
		// Layers have no successors.
		return nil, nil
	}

	raw, err := orascontent.FetchAll(ctx, fetcher, desc)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}

	manifest := &v1.Manifest{}
	if err := json.Unmarshal(raw, manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	layer, runtimeFormat, err := selectLayer(manifest, s.platform)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.layer, s.runtimeFormat = layer, runtimeFormat
	s.mu.Unlock()

	return []v1.Descriptor{*layer}, nil
}

// result returns the selected layer, together with whether the artifact uses
// the KEP-6061 runtime format. ok is false if no manifest got copied.
func (s *layerSelection) result() (layer *v1.Descriptor, runtimeFormat, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.layer, s.runtimeFormat, s.layer != nil
}

// isIndex reports whether the media type is the one of an image index.
func isIndex(mediaType string) bool {
	return mediaType == v1.MediaTypeImageIndex || mediaType == mediaTypeDockerManifestList
}
