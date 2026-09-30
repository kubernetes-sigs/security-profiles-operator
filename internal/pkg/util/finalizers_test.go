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

package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func testConfigMap(finalizers ...string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Namespace:  "test-ns",
			Finalizers: finalizers,
		},
	}
}

func TestAddFinalizer(t *testing.T) {
	t.Parallel()

	t.Run("adds a missing finalizer", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap()
		c := fake.NewClientBuilder().
			WithScheme(utiltest.NewScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, AddFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"test-finalizer"}, obj.GetFinalizers())
	})

	t.Run("is a no-op when already present", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("test-finalizer")
		c := fake.NewClientBuilder().
			WithScheme(utiltest.NewScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, AddFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"test-finalizer"}, obj.GetFinalizers())
	})

	t.Run("fails when the object is gone", func(t *testing.T) {
		t.Parallel()

		c := fake.NewClientBuilder().WithScheme(utiltest.NewScheme(t)).Build()

		require.Error(t, AddFinalizer(t.Context(), c, testConfigMap(), "test-finalizer"))
	})
}

func TestRemoveFinalizer(t *testing.T) {
	t.Parallel()

	t.Run("removes a present finalizer", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("test-finalizer", "other")
		c := fake.NewClientBuilder().
			WithScheme(utiltest.NewScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, RemoveFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"other"}, obj.GetFinalizers())
	})

	t.Run("is a no-op when absent", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("other")
		c := fake.NewClientBuilder().
			WithScheme(utiltest.NewScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, RemoveFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"other"}, obj.GetFinalizers())
	})

	t.Run("fails when the object is gone", func(t *testing.T) {
		t.Parallel()

		c := fake.NewClientBuilder().WithScheme(utiltest.NewScheme(t)).Build()

		require.Error(t, RemoveFinalizer(t.Context(), c, testConfigMap(), "test-finalizer"))
	})
}

func TestRemoveFinalizers(t *testing.T) {
	t.Parallel()

	t.Run("removes every present finalizer with one update", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("first", "other", "second")
		c := fake.NewClientBuilder().
			WithScheme(utiltest.NewScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, RemoveFinalizers(t.Context(), c, obj, "first", "", "second", "absent"))
		require.Equal(t, []string{"other"}, obj.GetFinalizers())

		stored := &corev1.ConfigMap{}
		require.NoError(t, c.Get(t.Context(), NamespacedName("test", "test-ns"), stored))
		require.Equal(t, []string{"other"}, stored.GetFinalizers())
	})

	t.Run("does not update when nothing is present", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("other")
		c := fake.NewClientBuilder().
			WithScheme(utiltest.NewScheme(t)).WithObjects(obj.DeepCopy()).Build()

		before := &corev1.ConfigMap{}
		require.NoError(t, c.Get(t.Context(), NamespacedName("test", "test-ns"), before))

		require.NoError(t, RemoveFinalizers(t.Context(), c, obj, "", "absent"))

		after := &corev1.ConfigMap{}
		require.NoError(t, c.Get(t.Context(), NamespacedName("test", "test-ns"), after))
		require.Equal(t, []string{"other"}, after.GetFinalizers())
		require.Equal(t, before.GetResourceVersion(), after.GetResourceVersion())
	})
}

// A finalizer is a label-shaped string, so a long node name has to be
// shortened rather than producing a value the API server rejects. It used to
// be truncated, which made nodes whose names only differ past the cut share
// one finalizer.
func TestGetFinalizerNodeString(t *testing.T) {
	t.Parallel()

	longName := strings.Repeat("n", 200)
	maxFitting := strings.Repeat("n", validation.DNS1123LabelMaxLength-len(nodeFinalizerSuffix))

	t.Run("short node names are used as is", func(t *testing.T) {
		t.Parallel()

		require.Equal(t, "worker-1-deleted", GetFinalizerNodeString("worker-1"))
		require.Empty(t, GetLegacyFinalizerNodeString("worker-1"))
	})

	t.Run("long node names are shortened to the label limit", func(t *testing.T) {
		t.Parallel()

		got := GetFinalizerNodeString(longName)
		require.Len(t, got, validation.DNS1123LabelMaxLength)
		require.True(t, strings.HasSuffix(got, nodeFinalizerSuffix))
		require.True(t, strings.HasPrefix(got, longName[:nodeFinalizerHashPrefixLen]+"-"))
		require.Empty(t, validation.IsQualifiedName(got))
		require.Equal(t, got, GetFinalizerNodeString(longName), "shortening is deterministic")
	})

	t.Run("a name at exactly the limit still fits", func(t *testing.T) {
		t.Parallel()

		got := GetFinalizerNodeString(maxFitting)
		require.Len(t, got, validation.DNS1123LabelMaxLength)
		require.Equal(t, maxFitting+nodeFinalizerSuffix, got)
		require.Empty(t, GetLegacyFinalizerNodeString(maxFitting))
	})

	t.Run("names differing only past the cut do not collide", func(t *testing.T) {
		t.Parallel()

		other := longName[:len(longName)-1] + "m"
		require.NotEqual(t, GetFinalizerNodeString(longName), GetFinalizerNodeString(other))

		// This is what the truncation of earlier releases did.
		require.Equal(
			t,
			GetLegacyFinalizerNodeString(longName),
			GetLegacyFinalizerNodeString(other),
		)
	})

	t.Run("the legacy form is the truncated name", func(t *testing.T) {
		t.Parallel()

		got := GetLegacyFinalizerNodeString(longName)
		require.Len(t, got, validation.DNS1123LabelMaxLength)
		require.Equal(t, strings.Repeat("n", 55)+nodeFinalizerSuffix, got)
		require.NotEqual(t, got, GetFinalizerNodeString(longName))
	})

	t.Run("node names with dots stay valid finalizers", func(t *testing.T) {
		t.Parallel()

		name := "worker-01.region-" + strings.Repeat("a", 60) + ".example.com"
		got := GetFinalizerNodeString(name)
		require.Len(t, got, validation.DNS1123LabelMaxLength)
		require.Empty(t, validation.IsQualifiedName(got))
	})
}
