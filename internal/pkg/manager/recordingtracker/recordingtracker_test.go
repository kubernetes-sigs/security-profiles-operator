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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

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

	for name, tc := range map[string]struct {
		annotations map[string]string
		wantTracked bool
	}{
		"recorded by the webhook": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_ctr_123_456",
			},
			wantTracked: true,
		},
		// For example a pod created before the recording.
		"not recorded by the webhook": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testPodMatchesRecording(t, tc.annotations, tc.wantTracked)
		})
	}
}

func testPodMatchesRecording(t *testing.T, annotations map[string]string, wantTracked bool) {
	t.Helper()

	scheme := utiltest.NewScheme(t)

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
			Name:        "test-pod",
			Namespace:   "default",
			Labels:      map[string]string{"app": "test"},
			Annotations: annotations,
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

	if !wantTracked {
		require.Empty(t, updated.Status.ActiveWorkloads)
		require.NotContains(t, updated.GetFinalizers(), finalizer)

		return
	}

	require.Contains(t, updated.Status.ActiveWorkloads, "test-pod")
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

func TestPodDoesNotMatchRecording(t *testing.T) {
	t.Parallel()

	scheme := utiltest.NewScheme(t)

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

func TestPodNoLongerMatchingRecording(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		annotations map[string]string
		phase       corev1.PodPhase
		wantTracked bool
	}{
		"untracked without recording annotation": {},
		"kept while still recorded": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_ctr_123_456",
			},
			wantTracked: true,
		},
		"untracked once completed": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_ctr_123_456",
			},
			phase: corev1.PodSucceeded,
		},
		"annotation of another recording": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "other-recording_ctr_123_456",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

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
						MatchLabels: map[string]string{"app": "recorded"},
					},
				},
				Status: profilerecordingapi.ProfileRecordingStatus{
					ActiveWorkloads: []string{"test-pod"},
				},
			}

			// The labels of the pod changed after it got tracked.
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-pod",
					Namespace:   "default",
					Labels:      map[string]string{"app": "other"},
					Annotations: tc.annotations,
				},
				Status: corev1.PodStatus{Phase: tc.phase},
			}

			c := fake.NewClientBuilder().
				WithScheme(utiltest.NewScheme(t)).
				WithStatusSubresource(recording).
				WithObjects(recording, pod).
				WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
				Build()

			_, err := newReconciler(c).Reconcile(t.Context(), reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(pod),
			})
			require.NoError(t, err)

			updated := &profilerecordingapi.ProfileRecording{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))

			if tc.wantTracked {
				require.Equal(t, []string{"test-pod"}, updated.Status.ActiveWorkloads)
				require.Contains(t, updated.GetFinalizers(), finalizer)
			} else {
				require.Empty(t, updated.Status.ActiveWorkloads)
				require.NotContains(t, updated.GetFinalizers(), finalizer)
			}
		})
	}
}

func TestPodDeletedRemovesFromActiveWorkloads(t *testing.T) {
	t.Parallel()

	scheme := utiltest.NewScheme(t)

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

	scheme := utiltest.NewScheme(t)

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

	scheme := utiltest.NewScheme(t)

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

func TestPodMatchesRecordingBeingDeleted(t *testing.T) {
	t.Parallel()

	scheme := utiltest.NewScheme(t)

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-recording",
			Namespace:         "default",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
			Finalizers:        []string{"other"},
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
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
			Annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_ctr_123_456",
			},
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
	require.NotContains(t, updated.GetFinalizers(), finalizer)
}

func TestActiveWorkloadRequestsReleasesStalePods(t *testing.T) {
	t.Parallel()

	scheme := utiltest.NewScheme(t)

	// The pod got deleted while the operator was down, so no delete event
	// for it will ever be observed.
	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-recording",
			Namespace:  "default",
			Finalizers: []string{finalizer},
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

	requests := activeWorkloadRequests(t.Context(), recording)
	require.Equal(t, []reconcile.Request{{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "deleted-pod"},
	}}, requests)

	for _, req := range requests {
		_, err := r.Reconcile(t.Context(), req)
		require.NoError(t, err)
	}

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Empty(t, updated.Status.ActiveWorkloads)
	require.NotContains(t, updated.GetFinalizers(), finalizer)
}

func recordedPod() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_ctr_123_456",
			},
		},
	}
}

func testRecording() *profilerecordingapi.ProfileRecording {
	return &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "test-recording", Namespace: "default"},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: profilerecordingapi.ProfileRecorderBpf,
		},
	}
}

// A pod which the cached recording tracks already costs no API request.
func TestTrackedPodSkipsAPIRequests(t *testing.T) {
	t.Parallel()

	recording := testRecording()
	recording.Finalizers = []string{finalizer}
	recording.Status.ActiveWorkloads = []string{"test-pod"}

	writes := 0
	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithStatusSubresource(recording).
		WithObjects(recording, recordedPod()).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
			) error {
				writes++

				return c.Update(ctx, obj, opts...)
			},
			SubResourcePatch: func(
				ctx context.Context, c client.Client, sub string, obj client.Object,
				patch client.Patch, opts ...client.SubResourcePatchOption,
			) error {
				writes++

				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	reads := 0
	r := newReconciler(c)
	r.reader = countingReader{Reader: c, reads: &reads}

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(recordedPod()),
	})
	require.NoError(t, err)
	require.Zero(t, reads)
	require.Zero(t, writes)
}

// countingReader counts the uncached reads.
type countingReader struct {
	client.Reader

	reads *int
}

func (c countingReader) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	*c.reads++

	return c.Reader.Get(ctx, key, obj, opts...)
}

// A conflict while tracking a pod gets retried with a fresh read.
func TestTrackPodRetriesConflict(t *testing.T) {
	t.Parallel()

	recording := testRecording()

	conflicts := 1
	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithStatusSubresource(recording).
		WithObjects(recording, recordedPod()).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context, c client.Client, sub string, obj client.Object,
				patch client.Patch, opts ...client.SubResourcePatchOption,
			) error {
				if conflicts > 0 {
					conflicts--

					return apierrors.NewConflict(
						profilerecordingapi.GroupVersion.WithResource("profilerecordings").
							GroupResource(),
						obj.GetName(),
						errors.New("test"),
					)
				}

				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	_, err := newReconciler(c).Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(recordedPod()),
	})
	require.NoError(t, err)
	require.Zero(t, conflicts)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Equal(t, []string{"test-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

// A recording which got deleted after it was listed is skipped without an
// error and without being recreated.
func TestTrackPodDeletedRecording(t *testing.T) {
	t.Parallel()

	recording := testRecording()
	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithStatusSubresource(recording).
		WithObjects(recordedPod()).
		Build()

	require.NoError(t, newReconciler(c).trackPod(t.Context(), recording, "test-pod"))

	err := c.Get(
		t.Context(),
		client.ObjectKeyFromObject(recording),
		&profilerecordingapi.ProfileRecording{},
	)
	require.True(t, apierrors.IsNotFound(err))
}

// hookReader calls afterGet after every uncached read with the number of the
// read.
type hookReader struct {
	client.Reader

	reads    *int
	afterGet func(n int)
}

func (h hookReader) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	*h.reads++

	err := h.Reader.Get(ctx, key, obj, opts...)

	h.afterGet(*h.reads)

	return err
}

// A pod which another reconcile tracks while the last tracked pod gets
// untracked keeps the finalizer in place. The removal of the finalizer is
// written for the recording as read, so it conflicts with the concurrent
// status update, and the retry sees the new pod.
func TestUntrackPodKeepsFinalizerForConcurrentlyTrackedPod(t *testing.T) {
	t.Parallel()

	recording := testRecording()
	recording.Finalizers = []string{finalizer}
	recording.Status.ActiveWorkloads = []string{"deleted-pod"}

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithStatusSubresource(recording).
		WithObjects(recording).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	reads := 0
	r := newReconciler(c)
	r.reader = hookReader{Reader: c, reads: &reads, afterGet: func(n int) {
		// The second read checks whether the finalizer can go.
		if n != 2 {
			return
		}

		concurrent := &profilerecordingapi.ProfileRecording{}
		require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), concurrent))
		concurrent.Status.ActiveWorkloads = append(concurrent.Status.ActiveWorkloads, "new-pod")
		require.NoError(t, c.Status().Update(t.Context(), concurrent))
	}}

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "deleted-pod"},
	})
	require.NoError(t, err)
	require.Greater(t, reads, 2, "the finalizer removal got retried")

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Equal(t, []string{"new-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)
}
