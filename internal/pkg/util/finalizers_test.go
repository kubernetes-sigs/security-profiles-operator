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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	return scheme
}

func TestAddFinalizer(t *testing.T) {
	t.Parallel()

	t.Run("adds a missing finalizer", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap()
		c := fake.NewClientBuilder().
			WithScheme(testScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, AddFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"test-finalizer"}, obj.GetFinalizers())
	})

	t.Run("is a no-op when already present", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("test-finalizer")
		c := fake.NewClientBuilder().
			WithScheme(testScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, AddFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"test-finalizer"}, obj.GetFinalizers())
	})

	t.Run("fails when the object is gone", func(t *testing.T) {
		t.Parallel()

		c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

		require.Error(t, AddFinalizer(t.Context(), c, testConfigMap(), "test-finalizer"))
	})
}

func TestRemoveFinalizer(t *testing.T) {
	t.Parallel()

	t.Run("removes a present finalizer", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("test-finalizer", "other")
		c := fake.NewClientBuilder().
			WithScheme(testScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, RemoveFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"other"}, obj.GetFinalizers())
	})

	t.Run("is a no-op when absent", func(t *testing.T) {
		t.Parallel()

		obj := testConfigMap("other")
		c := fake.NewClientBuilder().
			WithScheme(testScheme(t)).WithObjects(obj.DeepCopy()).Build()

		require.NoError(t, RemoveFinalizer(t.Context(), c, obj, "test-finalizer"))
		require.Equal(t, []string{"other"}, obj.GetFinalizers())
	})

	t.Run("fails when the object is gone", func(t *testing.T) {
		t.Parallel()

		c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

		require.Error(t, RemoveFinalizer(t.Context(), c, testConfigMap(), "test-finalizer"))
	})
}

// A finalizer is a label-shaped string, so a long node name has to be truncated
// rather than producing a value the API server rejects.
func TestGetFinalizerNodeString(t *testing.T) {
	t.Parallel()

	t.Run("short node names are used as is", func(t *testing.T) {
		t.Parallel()

		require.Equal(t, "worker-1-deleted", GetFinalizerNodeString("worker-1"))
	})

	t.Run("long node names are truncated to the label limit", func(t *testing.T) {
		t.Parallel()

		got := GetFinalizerNodeString(strings.Repeat("n", 200))
		require.Len(t, got, validation.DNS1123LabelMaxLength)
		require.True(t, strings.HasSuffix(got, "-deleted"))
	})

	t.Run("a name at exactly the limit still fits", func(t *testing.T) {
		t.Parallel()

		name := strings.Repeat("n", validation.DNS1123LabelMaxLength-len("-deleted"))
		got := GetFinalizerNodeString(name)
		require.Len(t, got, validation.DNS1123LabelMaxLength)
		require.Equal(t, name+"-deleted", got)
	})
}
