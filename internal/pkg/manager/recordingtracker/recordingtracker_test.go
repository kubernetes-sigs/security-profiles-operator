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

package recordingtracker

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

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, profilerecordingapi.AddToScheme(s))

	return s
}

func newReconciler(c client.Client) *RecordingTrackerReconciler {
	return &RecordingTrackerReconciler{
		client: c,
		reader: c,
		log:    logr.Discard(),
	}
}

func recordingIndexFunc(obj client.Object) []string {
	pr, ok := obj.(*profilerecordingapi.ProfileRecording)
	if !ok {
		return nil
	}

	return pr.Status.ActiveWorkloads
}

func TestPodMatchesRecording(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-recording",
			Namespace: "default",
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: profilerecordingapi.ProfileRecorderBpf,
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
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
		WithStatusSubresource(recording).
		WithObjects(recording, pod).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(pod),
	})
	require.NoError(t, err)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Contains(t, updated.Status.ActiveWorkloads, "test-pod")
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

func TestPodDoesNotMatchRecording(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-recording",
			Namespace: "default",
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: profilerecordingapi.ProfileRecorderBpf,
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
		WithStatusSubresource(recording).
		WithObjects(recording, pod).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(pod),
	})
	require.NoError(t, err)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Empty(t, updated.Status.ActiveWorkloads)
	require.Empty(t, updated.GetFinalizers())
}

func TestPodDeletedRemovesFromActiveWorkloads(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-recording",
			Namespace:  "default",
			Finalizers: []string{finalizer},
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: profilerecordingapi.ProfileRecorderBpf,
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
			},
		},
		Status: profilerecordingapi.ProfileRecordingStatus{
			ActiveWorkloads: []string{"deleted-pod"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(recording).
		WithObjects(recording).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "deleted-pod"},
	})
	require.NoError(t, err)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Empty(t, updated.Status.ActiveWorkloads)
	require.NotContains(t, updated.GetFinalizers(), finalizer)
}

func TestPodDeletedFinalizerKeptWhenOtherPodsTracked(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-recording",
			Namespace:  "default",
			Finalizers: []string{finalizer},
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: profilerecordingapi.ProfileRecorderBpf,
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
			},
		},
		Status: profilerecordingapi.ProfileRecordingStatus{
			ActiveWorkloads: []string{"deleted-pod", "other-pod"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(recording).
		WithObjects(recording).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "deleted-pod"},
	})
	require.NoError(t, err)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Equal(t, []string{"other-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

func TestNoRecordingsInNamespace(t *testing.T) {
	t.Parallel()

	scheme := newTestScheme(t)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pod).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	r := newReconciler(c)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(pod),
	})
	require.NoError(t, err)
}
