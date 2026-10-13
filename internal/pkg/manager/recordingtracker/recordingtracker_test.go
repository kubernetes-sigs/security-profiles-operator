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
	"fmt"
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
		// The recording webhook does not see annotations added after the
		// creation of the pod, and the daemon does not record them.
		"annotation of another recorder": {
			annotations: map[string]string{
				config.SeccompProfileRecordLogsAnnotationKey + "ctr": "test-recording_ctr_123_456",
			},
		},
		"annotation of a missing container": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "other": "test-recording_other_123_456",
			},
		},
		"annotation naming another container": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_other_123_456",
			},
		},
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
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
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

	recorded := map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": "test-recording_ctr_123_456",
	}

	for name, tc := range map[string]struct {
		annotations map[string]string
		labels      map[string]string
		phase       corev1.PodPhase
		wantTracked bool
	}{
		"untracked without recording annotation": {labels: map[string]string{"app": "recorded"}},
		"kept while still recorded": {
			annotations: recorded,
			labels:      map[string]string{"app": "recorded"},
			wantTracked: true,
		},
		// The daemon checks the selector when the container starts and keeps
		// recording the pod afterwards.
		"kept once the labels changed": {
			annotations: recorded,
			labels:      map[string]string{"app": "other"},
			wantTracked: true,
		},
		"untracked once completed": {
			annotations: recorded,
			labels:      map[string]string{"app": "recorded"},
			phase:       corev1.PodSucceeded,
		},
		"annotation of another recording": {
			annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "ctr": "other-recording_ctr_123_456",
			},
			labels: map[string]string{"app": "recorded"},
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

			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-pod",
					Namespace:   "default",
					Labels:      tc.labels,
					Annotations: tc.annotations,
				},
				Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
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
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
	}
}

// testRecording returns a recording which selects every pod.
func testRecording() *profilerecordingapi.ProfileRecording {
	return &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "test-recording", Namespace: "default"},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder:    profilerecordingapi.ProfileRecorderBpf,
			PodSelector: &metav1.LabelSelector{},
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
		// The status gets written as cached, the first read checks whether
		// the finalizer can go.
		if n != 1 {
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
	require.Greater(t, reads, 1, "the finalizer removal got retried")

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Equal(t, []string{"new-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

// A recording whose last listed pod goes away gets filled up with the other
// recorded pods, which a full list did not take, so that it keeps its
// finalizer.
func TestEmptiedRecordingGetsFilledUp(t *testing.T) {
	t.Parallel()

	recording := testRecording()
	recording.Finalizers = []string{finalizer}
	recording.Status.ActiveWorkloads = []string{"listed"}

	recording.Spec.PodSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "recorded"},
	}

	recorded := recordedPod()
	recorded.Labels = map[string]string{"app": "recorded"}

	// The pod got relabeled after the webhook annotated it at its admission,
	// which counts like a tracked pod.
	relabeled := recordedPod()
	relabeled.Name = "relabeled"
	relabeled.CreationTimestamp = metav1.Unix(456, 0)

	// The annotation of a pod which the recording does not select got added
	// long after its creation, by the pod author, so it does not count.
	forged := recordedPod()
	forged.Name = "forged"
	forged.CreationTimestamp = metav1.Unix(0, 0)

	completed := recordedPod()
	completed.Name = "completed"
	completed.Status.Phase = corev1.PodSucceeded

	other := recordedPod()
	other.Name = "other"
	other.Annotations = map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": "other-recording_ctr_123_456",
	}

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithStatusSubresource(recording).
		WithObjects(recording, recorded, relabeled, forged, completed, other).
		WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
		Build()

	_, err := newReconciler(c).Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "listed"},
	})
	require.NoError(t, err)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))
	require.Equal(t, []string{"relabeled", "test-pod"}, updated.Status.ActiveWorkloads)
	require.Contains(t, updated.GetFinalizers(), finalizer)
}

// A tracked pod stays tracked while it carries an annotation of the recording,
// like the daemon keeps recording it, while a pod gets tracked anew only if
// the recording selects it. Otherwise an edited recording would lose its
// finalizer and get merged without the profiles of its running pods.
func TestTrackedPodSurvivesRecordingChange(t *testing.T) {
	t.Parallel()

	for name, tracked := range map[string]bool{"tracked pod": true, "new pod": false} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// The recording selects other pods and containers by now.
			recording := testRecording()
			recording.Spec.PodSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "other"},
			}
			recording.Spec.Containers = []string{"other"}

			if tracked {
				recording.Finalizers = []string{finalizer}
				recording.Status.ActiveWorkloads = []string{"test-pod"}
			}

			c := fake.NewClientBuilder().
				WithScheme(utiltest.NewScheme(t)).
				WithStatusSubresource(recording).
				WithObjects(recording, recordedPod()).
				WithIndex(&profilerecordingapi.ProfileRecording{}, linkedPodsKey, recordingIndexFunc).
				Build()

			_, err := newReconciler(c).Reconcile(t.Context(), reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(recordedPod()),
			})
			require.NoError(t, err)

			updated := &profilerecordingapi.ProfileRecording{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))

			if tracked {
				require.Equal(t, []string{"test-pod"}, updated.Status.ActiveWorkloads)
				require.Contains(t, updated.GetFinalizers(), finalizer)
			} else {
				require.Empty(t, updated.Status.ActiveWorkloads)
				require.NotContains(t, updated.GetFinalizers(), finalizer)
			}
		})
	}
}

// A pod which the recording webhook annotated while it admitted the pod gets
// tracked anew also if the recording changed since, like the daemon records
// it. An annotation added after the creation of the pod has a later time and
// needs the recording to select the pod.
func TestPodAnnotatedAtAdmissionIsTracked(t *testing.T) {
	t.Parallel()

	created := time.Unix(1_700_000_000, 0)
	value := func(ctr string, at time.Time) string {
		return fmt.Sprintf("test-recording_%s_abcde_%d", ctr, at.Unix())
	}

	for name, tc := range map[string]struct {
		key, value  string
		created     time.Time
		wantTracked bool
	}{
		"annotated at admission": {
			key: "ctr", value: value("ctr", created.Add(-time.Second)), created: created,
			wantTracked: true,
		},
		"clocks differ": {
			key: "ctr", value: value("ctr", created.Add(30*time.Second)), created: created,
			wantTracked: true,
		},
		"annotated after the creation": {
			key: "ctr", value: value("ctr", created.Add(time.Hour)), created: created,
		},
		"pod without creation time": {key: "ctr", value: value("ctr", created)},
		"missing container": {
			key: "other", value: value("other", created), created: created,
		},
		"invalid time": {
			key: "ctr", value: "test-recording_ctr_abcde_now", created: created,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// The recording selects other pods and containers by now.
			recording := testRecording()
			recording.Spec.PodSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "other"},
			}
			recording.Spec.Containers = []string{"other"}

			pod := recordedPod()
			pod.CreationTimestamp = metav1.NewTime(tc.created)
			pod.Annotations = map[string]string{
				config.SeccompProfileRecordLogsAnnotationKey + tc.key: tc.value,
			}

			require.Equal(t, tc.wantTracked, podRecordedBy(pod, recording, false))

			// A tracked pod stays tracked with any annotation of the
			// recording.
			require.True(t, podRecordedBy(pod, recording, true))
		})
	}
}
