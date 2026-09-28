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
	"fmt"
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

	pod := testPod(nil, "test-image")
	pod.Annotations = map[string]string{
		profilebindingapi.AppliedBindingsAnnotation: "test-binding",
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

func testPod(podLabels map[string]string, images ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    podLabels,
		},
	}

	for i, image := range images {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
			Name:  fmt.Sprintf("ctr-%d", i),
			Image: image,
		})
	}

	return pod
}

func testBinding(image string, activeWorkloads ...string) *profilebindingapi.ProfileBinding {
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
			Image: image,
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "bound"},
			},
		},
		Status: profilebindingapi.ProfileBindingStatus{ActiveWorkloads: activeWorkloads},
	}

	if len(activeWorkloads) > 0 {
		binding.Finalizers = []string{finalizer}
	}

	return binding
}

func reconcileTestPod(
	t *testing.T, binding *profilebindingapi.ProfileBinding, pod *corev1.Pod,
) *profilebindingapi.ProfileBinding {
	t.Helper()

	c := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithStatusSubresource(binding).
		WithObjects(binding, pod).
		WithIndex(&profilebindingapi.ProfileBinding{}, linkedPodsKey, bindingIndexFunc).
		Build()

	_, err := newReconciler(c).Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(pod),
	})
	require.NoError(t, err)

	updated := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))

	return updated
}

func TestPodMatchesBindingImage(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		bindingImage string
		podImages    []string
		wantTracked  bool
	}{
		"matching image": {
			bindingImage: "nginx", podImages: []string{"busybox", "nginx"}, wantTracked: true,
		},
		"wildcard image": {
			bindingImage: profilebindingapi.SelectAllContainersImage,
			podImages:    []string{"busybox"},
			wantTracked:  true,
		},
		"other image":        {bindingImage: "nginx", podImages: []string{"busybox"}},
		"pod without images": {bindingImage: "nginx"},
		"wildcard empty pod": {bindingImage: profilebindingapi.SelectAllContainersImage, wantTracked: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Pods created before the binding webhook annotated them stay
			// tracked while they match the binding.
			updated := reconcileTestPod(t, testBinding(tc.bindingImage, "default/test-pod"),
				testPod(map[string]string{"app": "bound"}, tc.podImages...))

			if tc.wantTracked {
				require.Equal(t, []string{"default/test-pod"}, updated.Status.ActiveWorkloads)
			} else {
				require.Empty(t, updated.Status.ActiveWorkloads)
				require.NotContains(t, updated.GetFinalizers(), finalizer)
			}
		})
	}
}

func TestInitContainerImageMatchesBinding(t *testing.T) {
	t.Parallel()

	pod := testPod(map[string]string{"app": "bound"}, "busybox")
	pod.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "nginx"}}

	updated := reconcileTestPod(t, testBinding("nginx", "default/test-pod"), pod)
	require.Equal(t, []string{"default/test-pod"}, updated.Status.ActiveWorkloads)
}

// Pods used to be tracked when they matched a binding, even if the webhook
// never applied it, for example in a namespace without binding enabled. Only
// the bindings the webhook recorded on the pod are tracked now.
func TestPodTrackedByAppliedBindings(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		annotation     *string
		tracked        bool
		podLabels      map[string]string
		ephemeralImage string
		wantTracked    bool
	}{
		"applied binding": {
			annotation: new("other,test-binding"), podLabels: map[string]string{"app": "bound"},
			wantTracked: true,
		},
		"applied binding, labels changed afterwards": {
			annotation: new("test-binding"), podLabels: map[string]string{"app": "other"},
			wantTracked: true,
		},
		"matching pod without annotation is not tracked anew": {
			podLabels: map[string]string{"app": "bound"},
		},
		"matching pod with other bindings": {
			annotation: new("other"), podLabels: map[string]string{"app": "bound"},
		},
		"tracked pod with other bindings gets untracked": {
			annotation: new("other"), tracked: true, podLabels: map[string]string{"app": "bound"},
		},
		"tracked pod without applied bindings gets untracked": {
			annotation: new(""), tracked: true, podLabels: map[string]string{"app": "bound"},
		},
		"binding applied to an ephemeral container": {
			annotation: new("other"), podLabels: map[string]string{"app": "bound"},
			ephemeralImage: "debug", wantTracked: true,
		},
		"ephemeral container of a pod not matching the selector": {
			annotation: new("other"), podLabels: map[string]string{"app": "other"},
			ephemeralImage: "debug",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			binding := testBinding("nginx")
			if tc.tracked {
				binding = testBinding("nginx", "default/test-pod")
			}

			pod := testPod(tc.podLabels, "nginx")
			if tc.ephemeralImage != "" {
				binding.Spec.Image = tc.ephemeralImage
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{
						Name: "debugger", Image: tc.ephemeralImage,
					},
				}}
			}

			if tc.annotation != nil {
				pod.Annotations = map[string]string{
					profilebindingapi.AppliedBindingsAnnotation: *tc.annotation,
				}
			}

			updated := reconcileTestPod(t, binding, pod)

			if tc.wantTracked {
				require.Equal(t, []string{"default/test-pod"}, updated.Status.ActiveWorkloads)
				require.Contains(t, updated.GetFinalizers(), finalizer)
			} else {
				require.Empty(t, updated.Status.ActiveWorkloads)
				require.NotContains(t, updated.GetFinalizers(), finalizer)
			}
		})
	}
}

func TestPodNoLongerMatchingIsUntracked(t *testing.T) {
	t.Parallel()

	// The pod was tracked, but its labels do not match anymore.
	updated := reconcileTestPod(t,
		testBinding("nginx", "default/test-pod", "default/other-pod"),
		testPod(map[string]string{"app": "other"}, "nginx"))
	require.Equal(t, []string{"default/other-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)

	// Without other pods, the finalizer goes away as well.
	updated = reconcileTestPod(t,
		testBinding("nginx", "default/test-pod"),
		testPod(map[string]string{"app": "other"}, "nginx"))
	require.Empty(t, updated.Status.ActiveWorkloads)
	require.NotContains(t, updated.GetFinalizers(), finalizer)
}

func TestDeletingBindingDoesNotTrackNewPods(t *testing.T) {
	t.Parallel()

	binding := testBinding("nginx", "default/other-pod")
	now := metav1.Now()
	binding.DeletionTimestamp = &now

	updated := reconcileTestPod(t, binding, testPod(map[string]string{"app": "bound"}, "nginx"))
	require.Equal(t, []string{"default/other-pod"}, updated.Status.ActiveWorkloads)
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

func TestActiveWorkloadRequests(t *testing.T) {
	t.Parallel()

	binding := &profilebindingapi.ProfileBinding{
		Status: profilebindingapi.ProfileBindingStatus{
			ActiveWorkloads: []string{"default/pod-a", "invalid", "other/pod-b"},
		},
	}

	require.Equal(t, []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: "default", Name: "pod-a"}},
		{NamespacedName: client.ObjectKey{Namespace: "other", Name: "pod-b"}},
	}, activeWorkloadRequests(t.Context(), binding))
	require.Empty(t, activeWorkloadRequests(t.Context(), &corev1.Pod{}))
}
