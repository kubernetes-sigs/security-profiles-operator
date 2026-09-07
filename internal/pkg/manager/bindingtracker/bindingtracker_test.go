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

package bindingtracker

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, profilebindingapi.AddToScheme(s))

	return s
}

func newReconciler(c client.Client) *BindingTrackerReconciler {
	return &BindingTrackerReconciler{
		client: c,
		reader: c,
		log:    logr.Discard(),
	}
}

func bindingIndexFunc(obj client.Object) []string {
	pb, ok := obj.(*profilebindingapi.ProfileBinding)
	if !ok {
		return nil
	}

	return pb.Status.ActiveWorkloads
}

func TestPodMatchesBindingNilSelector(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	binding := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "default",
		},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: "test-profile",
			},
			Image: "test-image",
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(binding).
		WithObjects(binding, pod).
		WithIndex(&profilebindingapi.ProfileBinding{}, linkedPodsKey, bindingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(pod),
	})
	require.NoError(t, err)

	updated := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))
	require.Contains(t, updated.Status.ActiveWorkloads, "default/test-pod")
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

func TestPodDoesNotMatchBindingSelector(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	binding := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "default",
		},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: "test-profile",
			},
			Image: "test-image",
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "other"},
			},
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(binding).
		WithObjects(binding, pod).
		WithIndex(&profilebindingapi.ProfileBinding{}, linkedPodsKey, bindingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(pod),
	})
	require.NoError(t, err)

	updated := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))
	require.Empty(t, updated.Status.ActiveWorkloads)
	require.Empty(t, updated.GetFinalizers())
}

func TestPodDeletedRemovesFromActiveWorkloads(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	podID := "default/deleted-pod"
	binding := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "default",
			Finalizers: []string{finalizer},
		},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: "test-profile",
			},
			Image: "test-image",
		},
		Status: profilebindingapi.ProfileBindingStatus{
			ActiveWorkloads: []string{podID},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(binding).
		WithObjects(binding).
		WithIndex(&profilebindingapi.ProfileBinding{}, linkedPodsKey, bindingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "deleted-pod"},
	})
	require.NoError(t, err)

	updated := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))
	require.Empty(t, updated.Status.ActiveWorkloads)
	require.NotContains(t, updated.GetFinalizers(), finalizer)
}

func TestPodDeletedFinalizerKeptWhenOtherPodsTracked(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	binding := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "default",
			Finalizers: []string{finalizer},
		},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: "test-profile",
			},
			Image: "test-image",
		},
		Status: profilebindingapi.ProfileBindingStatus{
			ActiveWorkloads: []string{"default/deleted-pod", "default/other-pod"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(binding).
		WithObjects(binding).
		WithIndex(&profilebindingapi.ProfileBinding{}, linkedPodsKey, bindingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "deleted-pod"},
	})
	require.NoError(t, err)

	updated := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))
	require.Equal(t, []string{"default/other-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)
}
