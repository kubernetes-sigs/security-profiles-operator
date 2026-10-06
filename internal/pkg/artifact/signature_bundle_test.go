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
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	ggcrname "github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	ggcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

const promotionPredicateType = "https://k8s.io/promo-tools/promotion/v1"

// pushWithReferrers pushes an artifact to the in-memory registry, with one
// bundle referrer per predicate type, written with go-containerregistry like
// cosign does, and returns the descriptor of the artifact manifest.
func pushWithReferrers(
	t *testing.T, host, repo string, predicateTypes ...string,
) ocispec.Descriptor {
	t.Helper()

	artifact := mutate.ConfigMediaType(
		mutate.MediaType(
			empty.Image,
			ggcrtypes.OCIManifestSchema1,
		),
		ggcrtypes.OCIConfigJSON,
	)
	artifact, err := mutate.AppendLayers(
		artifact, static.NewLayer([]byte(repo), "application/json"),
	)
	require.NoError(t, err)

	ref, err := ggcrname.ParseReference(host+"/"+repo+":v1", ggcrname.Insecure)
	require.NoError(t, err)
	require.NoError(t, ggcrremote.Write(ref, artifact))

	desc, err := ggcrremote.Head(ref)
	require.NoError(t, err)

	for i, predicateType := range predicateTypes {
		// Distinct content per bundle, so every referrer gets its own digest.
		layer := static.NewLayer([]byte(predicateType+strconv.Itoa(i)), bundleMediaType)
		referrer, err := mutate.AppendLayers(
			mutate.ConfigMediaType(
				mutate.MediaType(empty.Image, ggcrtypes.OCIManifestSchema1),
				ggcrtypes.OCIConfigJSON,
			),
			layer,
		)
		require.NoError(t, err)

		// The subject has to be set last, annotating drops it.
		annotated, ok := mutate.Annotations(
			referrer, map[string]string{annotationBundlePredicateType: predicateType},
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

	return ocispec.Descriptor{
		MediaType: string(desc.MediaType),
		Digest:    digest.Digest(desc.Digest.String()),
		Size:      desc.Size,
	}
}

// TestSignatureCandidates attaches bundle referrers to an artifact in an
// in-memory registry, written with go-containerregistry like cosign does,
// and checks which ones count as signature.
func TestSignatureCandidates(t *testing.T) {
	t.Parallel()

	for _, referrersAPI := range []bool{true, false} {
		host := testRegistry(t, referrersAPI)

		for _, tc := range []struct {
			name           string
			predicateTypes []string
			bundles        int
		}{
			{name: "none"},
			{name: "signature", predicateTypes: []string{cosignSignPredicateType}, bundles: 1},
			{name: "attestation", predicateTypes: []string{promotionPredicateType}},
			{
				name:           "both",
				predicateTypes: []string{promotionPredicateType, cosignSignPredicateType, cosignSignPredicateType},
				bundles:        2,
			},
		} {
			t.Run(tc.name+" "+strconv.FormatBool(referrersAPI), func(t *testing.T) {
				t.Parallel()

				name := "profiles/" + tc.name
				subject := pushWithReferrers(t, host, name, tc.predicateTypes...)

				candidates, legacy, err := New(logr.Discard()).signatureCandidates(
					t.Context(), testRepository(t, host, name), &subject,
				)
				require.NoError(t, err)
				require.Len(t, candidates, tc.bundles)

				// Without bundles, the legacy signature tag is looked up,
				// which does not exist either.
				require.Equal(t, tc.bundles == 0, legacy)
			})
		}
	}
}

// TestSignatureReferrersLimits verifies that attestations do not count
// against the signature limit and that a pull considers at most
// maxSignatures signature bundles.
func TestSignatureReferrersLimits(t *testing.T) {
	t.Parallel()

	repeat := func(predicateType string, count int) []string {
		result := make([]string, count)
		for i := range result {
			result[i] = predicateType
		}

		return result
	}

	for _, tc := range []struct {
		name           string
		predicateTypes []string
		maxReferrers   int
		want           int
	}{
		{
			name: "many attestations",
			predicateTypes: append(
				repeat(promotionPredicateType, maxSignatures+4),
				cosignSignPredicateType, cosignSignPredicateType,
			),
			maxReferrers: maxReferrers,
			want:         2,
		},
		{
			name:           "too many signatures",
			predicateTypes: repeat(cosignSignPredicateType, maxSignatures+4),
			maxReferrers:   maxReferrers,
			want:           maxSignatures,
		},
		{
			// The listing stops after maxReferrers referrers, even if
			// fewer than maxSignatures of them are signatures.
			name:           "too many referrers",
			predicateTypes: repeat(cosignSignPredicateType, 8),
			maxReferrers:   3,
			want:           3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			host := testRegistry(t, true)
			subject := pushWithReferrers(t, host, "profiles/limits", tc.predicateTypes...)

			signatures, err := signatureReferrers(
				t.Context(), testRepository(t, host, "profiles/limits"), &subject,
				maxSignatures, tc.maxReferrers,
			)
			require.NoError(t, err)
			require.Len(t, signatures, tc.want)

			for i := range signatures {
				require.True(t, isSignatureReferrer(&signatures[i]))
			}
		})
	}
}
