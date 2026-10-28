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

package recordingkinds

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

// Every kind which a recording accepts has an entry, whose list holds objects
// of the kind.
func TestKinds(t *testing.T) {
	t.Parallel()

	for _, kind := range []profilerecordingapi.ProfileRecordingKind{
		profilerecordingapi.ProfileRecordingKindSeccompProfile,
		profilerecordingapi.ProfileRecordingKindSelinuxProfile,
		profilerecordingapi.ProfileRecordingKindAppArmorProfile,
	} {
		k, ok := Of(kind)
		require.True(t, ok, kind)
		require.Equal(t, kind, k.Kind)

		list := k.NewList()
		require.NoError(t, meta.SetList(list, []runtime.Object{k.NewObject()}), kind)
		require.Equal(t, 1, meta.LenList(list))
	}

	_, ok := Of("unknown")
	require.False(t, ok)
}

func TestRecordingNames(t *testing.T) {
	t.Parallel()

	require.Equal(t,
		[]string{"my", "my-recording", "my-recording-nginx"},
		RecordingNames("my-recording-nginx-abc12"))
	require.Equal(t, []string{"a", "a-"}, RecordingNames("a--b"))
	require.Empty(t, RecordingNames("-nginx"))
	require.Empty(t, RecordingNames("profile"))
}

// newCache returns a cache which is not started, so that its informers get
// created without an API server.
func newCache(t *testing.T, namespaces ...string) cache.Cache {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, profilerecordingapi.AddToScheme(scheme))

	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(
		profilerecordingapi.GroupVersion.WithKind("ProfileRecording"), meta.RESTScopeNamespace,
	)

	opts := cache.Options{Scheme: scheme, Mapper: mapper}
	if len(namespaces) > 0 {
		opts.DefaultNamespaces = map[string]cache.Config{}
		for _, namespace := range namespaces {
			opts.DefaultNamespaces[namespace] = cache.Config{}
		}
	}

	c, err := cache.New(&rest.Config{Host: "https://127.0.0.1:1"}, opts)
	require.NoError(t, err)

	return c
}

// The recording merger and the recording tracker both add the index, in any
// order, also to a cache restricted to namespaces.
func TestIndexRecordingNames(t *testing.T) {
	t.Parallel()

	for name, namespaces := range map[string][]string{
		"cluster":    nil,
		"namespaced": {"ns1", "ns2"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := newCache(t, namespaces...)

			require.NoError(t, IndexRecordingNames(t.Context(), c))
			require.NoError(t, IndexRecordingNames(t.Context(), c))

			// The informer rejects adding the index again.
			require.Error(t, c.IndexField(
				t.Context(), &profilerecordingapi.ProfileRecording{},
				RecordingNameKey, RecordingNameIndex,
			))

			// Another cache gets the index as well.
			require.NoError(t, IndexRecordingNames(t.Context(), newCache(t, namespaces...)))
		})
	}
}

var errIndex = errors.New("index")

// failingIndexer fails to add the first index.
type failingIndexer struct {
	calls int
}

func (f *failingIndexer) IndexField(
	context.Context, client.Object, string, client.IndexerFunc,
) error {
	f.calls++
	if f.calls == 1 {
		return errIndex
	}

	return nil
}

// An index which could not be added gets added on the next attempt.
func TestIndexRecordingNamesError(t *testing.T) {
	t.Parallel()

	indexer := &failingIndexer{}

	require.ErrorIs(t, IndexRecordingNames(t.Context(), indexer), errIndex)
	require.NoError(t, IndexRecordingNames(t.Context(), indexer))
	require.NoError(t, IndexRecordingNames(t.Context(), indexer))
	require.Equal(t, 2, indexer.calls)
}
