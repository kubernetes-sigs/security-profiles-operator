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
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/opencontainers/go-digest"
	imagespecs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote"
)

// TestPushPullRoundTrip pushes and pulls artifacts through an in-process
// registry, to verify the platform selection with the real ORAS copy.
func TestPushPullRoundTrip(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)

	host := strings.TrimPrefix(server.URL, "http://")
	sut := New(logr.Discard())
	pushOpts := &PushOptions{DisableSigning: true, PlainHTTP: true}
	pullOpts := &PullOptions{DisableSignatureVerification: true, PlainHTTP: true}

	profile := func(name string) string {
		path := filepath.Join(t.TempDir(), name+".yaml")
		require.NoError(t, os.WriteFile(path, []byte(
			"apiVersion: security-profiles-operator.x-k8s.io/v1\nkind: SeccompProfile\n"+
				"metadata:\n  name: "+name+"\nspec:\n  defaultAction: SCMP_ACT_ERRNO\n",
		), 0o600))

		return path
	}

	pulledName := func(ref string, platform *ocispec.Platform) (string, error) {
		res, err := sut.Pull(t.Context(), host+ref, "", "", platform, pullOpts)
		if err != nil {
			return "", err
		}

		return res.SeccompProfile().GetName(), nil
	}

	amd64 := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := &ocispec.Platform{OS: "linux", Architecture: "arm64"}
	arm64v8 := &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	s390x := &ocispec.Platform{OS: "linux", Architecture: "s390x"}

	require.NoError(t, sut.Push(t.Context(),
		map[*ocispec.Platform]string{nil: profile("neutral")},
		host+"/neutral:v1", "", "", nil, pushOpts,
	))

	for _, platform := range []*ocispec.Platform{nil, amd64, arm64v8, s390x} {
		name, err := pulledName("/neutral:v1", platform)
		require.NoError(t, err, platformToString(platform))
		require.Equal(t, "neutral", name)
	}

	require.NoError(t, sut.Push(t.Context(),
		map[*ocispec.Platform]string{amd64: profile("amd64"), arm64: profile("arm64")},
		host+"/multi:v1", "", "", nil, pushOpts,
	))

	name, err := pulledName("/multi:v1", arm64v8)
	require.NoError(t, err)
	require.Equal(t, "arm64", name)

	_, err = pulledName("/multi:v1", s390x)
	require.ErrorIs(t, err, ErrNoSingleLayer)

	// An index selects the manifest for the platform.
	repo, err := remote.NewRepository(host + "/multi")
	require.NoError(t, err)

	repo.PlainHTTP = true

	multiPlatform, err := repo.Resolve(t.Context(), "v1")
	require.NoError(t, err)

	multiPlatform.Platform = amd64

	require.NoError(t, sut.Push(t.Context(),
		map[*ocispec.Platform]string{nil: profile("s390x")},
		host+"/multi:s390x", "", "", nil, pushOpts,
	))

	s390xManifest, err := repo.Resolve(t.Context(), "s390x")
	require.NoError(t, err)

	s390xManifest.Platform = s390x

	index, err := json.Marshal(ocispec.Index{
		Versioned: imagespecs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{multiPlatform, s390xManifest},
	})
	require.NoError(t, err)
	require.NoError(t, repo.PushReference(t.Context(), ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageIndex,
		Digest:    digest.FromBytes(index),
		Size:      int64(len(index)),
	}, bytes.NewReader(index), "index"))

	name, err = pulledName("/multi:index", s390x)
	require.NoError(t, err)
	require.Equal(t, "s390x", name)

	name, err = pulledName("/multi:index", amd64)
	require.NoError(t, err)
	require.Equal(t, "amd64", name)

	_, err = pulledName("/multi:index", arm64)
	require.ErrorIs(t, err, ErrNoMatchingManifest)
}
