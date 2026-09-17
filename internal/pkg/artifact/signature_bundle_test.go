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
	"io"
	"log"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	ggcrname "github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cosignbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

const promotionPredicateType = "https://k8s.io/promo-tools/promotion/v1"

func TestHasSignatureBundle(t *testing.T) {
	t.Parallel()

	referrer := func(predicateType string) ggcrv1.Descriptor {
		return ggcrv1.Descriptor{
			ArtifactType: cosignbundle.BundleV03MediaType,
			Annotations:  map[string]string{ociremote.BundlePredicateType: predicateType},
		}
	}

	for _, tc := range []struct {
		name     string
		index    *ggcrv1.IndexManifest
		expected bool
	}{
		{name: "no index", index: nil},
		{name: "no referrers", index: &ggcrv1.IndexManifest{}},
		{
			name:     "signature bundle",
			index:    &ggcrv1.IndexManifest{Manifests: []ggcrv1.Descriptor{referrer(cosigntypes.CosignSignPredicateType)}},
			expected: true,
		},
		{
			name:  "attestation bundle only",
			index: &ggcrv1.IndexManifest{Manifests: []ggcrv1.Descriptor{referrer(promotionPredicateType)}},
		},
		{
			name: "attestation and signature bundle",
			index: &ggcrv1.IndexManifest{Manifests: []ggcrv1.Descriptor{
				referrer(promotionPredicateType), referrer(cosigntypes.CosignSignPredicateType),
			}},
			expected: true,
		},
		{
			name:  "referrer without annotations",
			index: &ggcrv1.IndexManifest{Manifests: []ggcrv1.Descriptor{{MediaType: ggcrtypes.OCIManifestSchema1}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expected, hasSignatureBundle(tc.index))
		})
	}
}

// TestSignatureBundleExists attaches bundle referrers like cosign does to an
// artifact in an in-memory registry and checks which ones select the bundle
// verification.
func TestSignatureBundleExists(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(registry.New(
		registry.WithReferrersSupport(true),
		registry.Logger(log.New(io.Discard, "", 0)),
	))
	t.Cleanup(s.Close)

	host := strings.TrimPrefix(s.URL, "http://")
	opts := &options.RegistryOptions{AllowHTTPRegistry: true}

	push := func(t *testing.T, repo string, predicateTypes ...string) string {
		t.Helper()

		artifact := mutate.ConfigMediaType(
			mutate.MediaType(empty.Image, ggcrtypes.OCIManifestSchema1), ggcrtypes.OCIConfigJSON,
		)
		artifact, err := mutate.AppendLayers(
			artifact, static.NewLayer([]byte(repo), "application/json"),
		)
		require.NoError(t, err)

		ref, err := ggcrname.ParseReference(host+"/"+repo+":v1", ggcrname.Insecure)
		require.NoError(t, err)
		require.NoError(t, ggcrremote.Write(ref, artifact))

		digest, err := artifact.Digest()
		require.NoError(t, err)

		desc, err := ggcrremote.Head(ref)
		require.NoError(t, err)

		for i, predicateType := range predicateTypes {
			// Distinct content per bundle, so every referrer gets its own digest.
			layer := static.NewLayer(
				[]byte(predicateType+strconv.Itoa(i)), cosignbundle.BundleV03MediaType,
			)
			referrer, err := mutate.AppendLayers(
				mutate.ConfigMediaType(
					mutate.MediaType(
						empty.Image,
						ggcrtypes.OCIManifestSchema1,
					),
					ggcrtypes.OCIConfigJSON,
				),
				layer,
			)
			require.NoError(t, err)

			// The subject has to be set last, annotating drops it.
			annotated, ok := mutate.Annotations(
				referrer, map[string]string{ociremote.BundlePredicateType: predicateType},
			).(ggcrv1.Image)
			require.True(t, ok)

			referrer, ok = mutate.Subject(annotated, *desc).(ggcrv1.Image)
			require.True(t, ok)

			referrerDigest, err := referrer.Digest()
			require.NoError(t, err)
			require.NoError(
				t,
				ggcrremote.Write(ref.Context().Digest(referrerDigest.String()), referrer),
			)
		}

		return host + "/" + repo + "@" + digest.String()
	}

	for _, tc := range []struct {
		name           string
		predicateTypes []string
		expected       bool
	}{
		{name: "none"},
		{name: "signature", predicateTypes: []string{cosigntypes.CosignSignPredicateType}, expected: true},
		{name: "attestation", predicateTypes: []string{promotionPredicateType}},
		{
			name:           "both",
			predicateTypes: []string{promotionPredicateType, cosigntypes.CosignSignPredicateType},
			expected:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			image := push(t, "profiles/"+tc.name, tc.predicateTypes...)

			exists, err := (&defaultImpl{}).SignatureBundleExists(t.Context(), image, opts)
			require.NoError(t, err)
			require.Equal(t, tc.expected, exists)
		})
	}
}
