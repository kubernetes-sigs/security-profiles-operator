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

package workloadtracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const testFinalizer = "test-finalizer"

var errTest = errors.New("test")

func newTracker(
	t *testing.T, funcs *interceptor.Funcs, objs ...client.Object,
) (*Tracker[*profilebindingapi.ProfileBinding], client.Client) {
	t.Helper()

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&profilebindingapi.ProfileBinding{}).
		WithInterceptorFuncs(*funcs).
		Build()

	return &Tracker[*profilebindingapi.ProfileBinding]{
		Client:    c,
		Reader:    c,
		Finalizer: testFinalizer,
		Kind:      "ProfileBinding",
		Workloads: func(pb *profilebindingapi.ProfileBinding) *[]string {
			return &pb.Status.ActiveWorkloads
		},
	}, c
}

func testBinding() *profilebindingapi.ProfileBinding {
	return &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "ns"},
	}
}

func stored(t *testing.T, c client.Client) *profilebindingapi.ProfileBinding {
	t.Helper()

	pb := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(testBinding()), pb))

	return pb
}

func TestTrackAndUntrack(t *testing.T) {
	t.Parallel()

	sut, c := newTracker(t, &interceptor.Funcs{}, testBinding())

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-b"))
	// Tracking a workload twice keeps it once.
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))

	pb := stored(t, c)
	require.Equal(t, []string{"pod-a", "pod-b"}, pb.Status.ActiveWorkloads)
	require.Contains(t, pb.Finalizers, testFinalizer)

	// The finalizer stays while a workload is left.
	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-a"))
	pb = stored(t, c)
	require.Equal(t, []string{"pod-b"}, pb.Status.ActiveWorkloads)
	require.Contains(t, pb.Finalizers, testFinalizer)

	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-b"))
	pb = stored(t, c)
	require.Empty(t, pb.Status.ActiveWorkloads)
	require.NotContains(t, pb.Finalizers, testFinalizer)
}

// The Reader is optional, the Client reads the objects without it.
func TestTrackAndUntrackWithoutReader(t *testing.T) {
	t.Parallel()

	sut, c := newTracker(t, &interceptor.Funcs{}, testBinding())
	sut.Reader = nil

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))

	pb := stored(t, c)
	require.Equal(t, []string{"pod-a"}, pb.Status.ActiveWorkloads)
	require.Contains(t, pb.Finalizers, testFinalizer)

	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-a"))

	pb = stored(t, c)
	require.Empty(t, pb.Status.ActiveWorkloads)
	require.NotContains(t, pb.Finalizers, testFinalizer)
}

func TestTrackRetriesConflicts(t *testing.T) {
	t.Parallel()

	conflicts := 0

	sut, c := newTracker(t, &interceptor.Funcs{
		SubResourcePatch: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			if conflicts == 0 {
				conflicts++

				return kerrors.NewConflict(schema.GroupResource{}, obj.GetName(), errTest)
			}

			return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}, testBinding())

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.Equal(t, 1, conflicts)
	require.Equal(t, []string{"pod-a"}, stored(t, c).Status.ActiveWorkloads)
}

func TestTrackMissingObject(t *testing.T) {
	t.Parallel()

	// An object which is gone has no workloads to track.
	sut, _ := newTracker(t, &interceptor.Funcs{})
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-a"))
}

func TestTrackErrors(t *testing.T) {
	t.Parallel()

	sut, _ := newTracker(t, &interceptor.Funcs{
		Get: func(
			context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption,
		) error {
			return errTest
		},
	}, testBinding())

	require.ErrorIs(t, sut.Track(t.Context(), testBinding(), "pod-a"), errTest)
	require.ErrorIs(t, sut.Untrack(t.Context(), testBinding(), "pod-a"), errTest)
}

// A write based on an outdated object fails with a conflict, so the retry
// keeps the workload which another reconcile tracked in the meantime.
func TestTrackKeepsConcurrentlyTrackedWorkload(t *testing.T) {
	t.Parallel()

	var c client.Client

	concurrent := false
	sut, c := newTracker(t, &interceptor.Funcs{
		SubResourcePatch: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			if !concurrent {
				concurrent = true

				other := &profilebindingapi.ProfileBinding{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(testBinding()), other))
				other.Status.ActiveWorkloads = []string{"pod-b"}
				require.NoError(t, cl.Status().Update(ctx, other))
			}

			return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}, testBinding())

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.Equal(t, []string{"pod-b", "pod-a"}, stored(t, c).Status.ActiveWorkloads)
}

// TestTrackAddsFinalizerRemovedConcurrently asserts that a workload tracked
// while the last one got untracked, which removed the finalizer, adds the
// finalizer again although the cache still shows it.
func TestTrackAddsFinalizerRemovedConcurrently(t *testing.T) {
	t.Parallel()

	binding := testBinding()
	binding.Finalizers = []string{testFinalizer}
	binding.Status.ActiveWorkloads = []string{"pod-a"}

	var c client.WithWatch

	concurrent := false
	c = fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(binding).
		WithStatusSubresource(&profilebindingapi.ProfileBinding{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context, cl client.Client, sub string, obj client.Object,
				patch client.Patch, opts ...client.SubResourcePatchOption,
			) error {
				if !concurrent {
					concurrent = true

					// The Untrack of the last workload drops it and the
					// finalizer before the patch lands.
					other := &profilebindingapi.ProfileBinding{}
					require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(testBinding()), other))
					other.Status.ActiveWorkloads = nil
					require.NoError(t, cl.Status().Update(ctx, other))
					require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(testBinding()), other))
					other.Finalizers = nil
					require.NoError(t, cl.Update(ctx, other))
				}

				return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	// The cache still shows the finalizer.
	stale := interceptor.NewClient(c, interceptor.Funcs{
		Get: func(
			ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption,
		) error {
			err := cl.Get(ctx, key, obj, opts...)
			if pb, ok := obj.(*profilebindingapi.ProfileBinding); ok && err == nil {
				pb.Finalizers = []string{testFinalizer}
			}

			return err
		},
	})

	sut := &Tracker[*profilebindingapi.ProfileBinding]{
		Client:    stale,
		Reader:    c,
		Finalizer: testFinalizer,
		Kind:      "ProfileBinding",
		Workloads: func(pb *profilebindingapi.ProfileBinding) *[]string {
			return &pb.Status.ActiveWorkloads
		},
	}

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-b"))
	require.Equal(t, []string{"pod-b"}, stored(t, c).Status.ActiveWorkloads)
	require.Equal(t, []string{testFinalizer}, stored(t, c).Finalizers)
}

// TestTrackAddsMissingFinalizerOfListedWorkload asserts that tracking a
// workload which is listed already adds the missing finalizer, although the
// cache still shows it. This happens if an earlier Track wrote the workload
// but failed to add the finalizer, which an Untrack had removed.
func TestTrackAddsMissingFinalizerOfListedWorkload(t *testing.T) {
	t.Parallel()

	binding := testBinding()
	binding.Status.ActiveWorkloads = []string{"pod-a"}

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(binding).
		WithStatusSubresource(&profilebindingapi.ProfileBinding{}).
		Build()

	// The cache still shows the finalizer.
	stale := interceptor.NewClient(c, interceptor.Funcs{
		Get: func(
			ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object,
			opts ...client.GetOption,
		) error {
			err := cl.Get(ctx, key, obj, opts...)
			if pb, ok := obj.(*profilebindingapi.ProfileBinding); ok && err == nil {
				pb.Finalizers = []string{testFinalizer}
			}

			return err
		},
	})

	sut := &Tracker[*profilebindingapi.ProfileBinding]{
		Client:    stale,
		Reader:    c,
		Finalizer: testFinalizer,
		Kind:      "ProfileBinding",
		Workloads: func(pb *profilebindingapi.ProfileBinding) *[]string {
			return &pb.Status.ActiveWorkloads
		},
	}

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.Equal(t, []string{"pod-a"}, stored(t, c).Status.ActiveWorkloads)
	require.Equal(t, []string{testFinalizer}, stored(t, c).Finalizers)
}

// The list of workloads is capped. It only gets filled up again from the
// users of the object once it runs empty, so that the finalizer stays while
// any workload uses the object, and the users are not looked up for every
// removed workload.
func TestTrackCapsWorkloads(t *testing.T) {
	t.Parallel()

	pb := testBinding()
	for i := range MaxWorkloads {
		pb.Status.ActiveWorkloads = append(pb.Status.ActiveWorkloads, fmt.Sprintf("pod-%04d", i))
	}

	sut, c := newTracker(t, &interceptor.Funcs{}, pb)

	userLookups := 0
	users := []string{"pod-z", "pod-x", "pod-0999", "pod-y"}
	sut.Users = func(context.Context, *profilebindingapi.ProfileBinding) ([]string, error) {
		userLookups++

		return users, nil
	}

	// A full list does not grow.
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-x"))
	require.Len(t, stored(t, c).Status.ActiveWorkloads, MaxWorkloads)
	require.NotContains(t, stored(t, c).Status.ActiveWorkloads, "pod-x")

	// The users are not looked up while workloads are left.
	for i := range MaxWorkloads - 1 {
		require.NoError(t, sut.Untrack(t.Context(), testBinding(), fmt.Sprintf("pod-%04d", i)))
	}

	require.Equal(t, []string{"pod-0999"}, stored(t, c).Status.ActiveWorkloads)
	require.Zero(t, userLookups)

	// The emptied list gets filled up with the other users in sort order.
	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-0999"))
	require.Equal(t, 1, userLookups)
	require.Equal(t, []string{"pod-x", "pod-y", "pod-z"}, stored(t, c).Status.ActiveWorkloads)
	require.Contains(t, stored(t, c).Finalizers, testFinalizer)

	// The finalizer goes once no user is left.
	users = nil

	for _, workload := range []string{"pod-x", "pod-y", "pod-z"} {
		require.NoError(t, sut.Untrack(t.Context(), testBinding(), workload))
	}

	require.Empty(t, stored(t, c).Status.ActiveWorkloads)
	require.NotContains(t, stored(t, c).Finalizers, testFinalizer)
}

// A failing lookup of the users keeps the last workload and the finalizer,
// which would go otherwise while users may be left, and the error lets the
// untrack get retried. Other workloads get removed without the lookup.
func TestUntrackUsersError(t *testing.T) {
	t.Parallel()

	pb := testBinding()
	pb.Finalizers = []string{testFinalizer}
	pb.Status.ActiveWorkloads = []string{"pod-a", "pod-b"}

	sut, c := newTracker(t, &interceptor.Funcs{}, pb)

	fail := true
	sut.Users = func(context.Context, *profilebindingapi.ProfileBinding) ([]string, error) {
		if fail {
			return nil, errTest
		}

		return nil, nil
	}

	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-a"))
	require.Equal(t, []string{"pod-b"}, stored(t, c).Status.ActiveWorkloads)

	require.ErrorIs(t, sut.Untrack(t.Context(), testBinding(), "pod-b"), errTest)
	require.Equal(t, []string{"pod-b"}, stored(t, c).Status.ActiveWorkloads)
	require.Contains(t, stored(t, c).Finalizers, testFinalizer)

	fail = false

	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-b"))
	require.Empty(t, stored(t, c).Status.ActiveWorkloads)
	require.NotContains(t, stored(t, c).Finalizers, testFinalizer)
}

// jsonReader reads like the API server client, which decodes the JSON of the
// object into the provided one and leaves the fields which the JSON omits as
// they are.
type jsonReader struct {
	client.Client
}

func (r jsonReader) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	stored := &profilebindingapi.ProfileBinding{}
	if err := r.Client.Get(ctx, key, stored, opts...); err != nil {
		return err
	}

	raw, err := json.Marshal(stored)
	if err != nil {
		return err
	}

	return json.Unmarshal(raw, obj)
}

// A write of an outdated object conflicts, and the retry reads the object
// again. Its empty list of workloads is left out of the JSON, so the outdated
// list must not survive the read, otherwise the finalizer never goes.
func TestUntrackConflictWithEmptyStoredList(t *testing.T) {
	t.Parallel()

	pb := testBinding()
	pb.Finalizers = []string{testFinalizer}

	sut, c := newTracker(t, &interceptor.Funcs{}, pb)
	sut.Reader = jsonReader{Client: c}

	outdated := stored(t, c)
	outdated.Status.ActiveWorkloads = []string{"pod-a"}
	outdated.ResourceVersion = "1"

	require.NoError(t, sut.Untrack(t.Context(), outdated, "pod-a"))
	require.NotContains(t, stored(t, c).Finalizers, testFinalizer)

	// The object of the caller stays as it is.
	require.Equal(t, []string{"pod-a"}, outdated.Status.ActiveWorkloads)
	require.Equal(t, []string{testFinalizer}, outdated.Finalizers)
}

// Tracking a workload with the cached object which has the finalizer costs no
// read from the API server, unless the write conflicts. Without the finalizer,
// it gets read for adding the finalizer, see
// TestTrackAddsFinalizerRemovedConcurrently.
func TestTrackWritesCachedObject(t *testing.T) {
	t.Parallel()

	pb := testBinding()
	pb.Finalizers = []string{testFinalizer}

	sut, c := newTracker(t, &interceptor.Funcs{}, pb)

	apiReads := 0
	sut.Reader = fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, _ client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				apiReads++

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	cached := stored(t, c)
	require.NoError(t, sut.Track(t.Context(), cached, "pod-a"))
	require.Zero(t, apiReads)
	require.Equal(t, []string{"pod-a"}, stored(t, c).Status.ActiveWorkloads)

	// An outdated object conflicts and gets read again.
	outdated := cached.DeepCopy()
	outdated.Status.ActiveWorkloads = nil
	outdated.ResourceVersion = "1"

	require.NoError(t, sut.Track(t.Context(), outdated, "pod-b"))
	require.Equal(t, 1, apiReads)
	require.Equal(t, []string{"pod-a", "pod-b"}, stored(t, c).Status.ActiveWorkloads)

	// An object which needs no change may be outdated, so it is read again.
	require.NoError(t, sut.Track(t.Context(), stored(t, c), "pod-b"))
	require.Equal(t, 2, apiReads)
}

// The finalizer gets added to the object which got written or read from the
// API server, without reading it again.
func TestTrackAddsFinalizerWithoutReadingAgain(t *testing.T) {
	t.Parallel()

	sut, c := newTracker(t, &interceptor.Funcs{}, testBinding())

	apiReads := 0
	sut.Reader = fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, _ client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				apiReads++

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	// The written cached object.
	require.NoError(t, sut.Track(t.Context(), stored(t, c), "pod-a"))
	require.Zero(t, apiReads)
	require.Equal(t, []string{testFinalizer}, stored(t, c).Finalizers)
	require.Equal(t, []string{"pod-a"}, stored(t, c).Status.ActiveWorkloads)

	// The object read from the API server, which needs no change.
	require.NoError(t, util.RemoveFinalizer(t.Context(), c, stored(t, c), testFinalizer))
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.Equal(t, 1, apiReads)
	require.Equal(t, []string{testFinalizer}, stored(t, c).Finalizers)
}

// A conflict of the finalizer patch reads the object from the API server and
// adds the finalizer to it.
func TestTrackAddsFinalizerAfterConflict(t *testing.T) {
	t.Parallel()

	conflicted := false
	sut, c := newTracker(t, &interceptor.Funcs{
		Patch: func(
			ctx context.Context, cl client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			if !conflicted {
				conflicted = true

				return kerrors.NewConflict(schema.GroupResource{}, obj.GetName(), errTest)
			}

			return cl.Patch(ctx, obj, patch, opts...)
		},
	}, testBinding())

	apiReads := 0
	sut.Reader = fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, _ client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				apiReads++

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	require.NoError(t, sut.Track(t.Context(), stored(t, c), "pod-a"))
	require.True(t, conflicted)
	require.Equal(t, 1, apiReads)
	require.Equal(t, []string{testFinalizer}, stored(t, c).Finalizers)
	require.Equal(t, []string{"pod-a"}, stored(t, c).Status.ActiveWorkloads)
}

// Tracking a workload with a full cached object which has the finalizer costs
// no request to the API server, as every event of every pod beyond the cap
// would do otherwise.
func TestTrackFullCachedObject(t *testing.T) {
	t.Parallel()

	pb := testBinding()
	pb.Finalizers = []string{testFinalizer}

	for i := range MaxWorkloads {
		pb.Status.ActiveWorkloads = append(pb.Status.ActiveWorkloads, fmt.Sprintf("pod-%04d", i))
	}

	requests := 0
	sut, c := newTracker(t, &interceptor.Funcs{
		Get: func(
			ctx context.Context, cl client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption,
		) error {
			requests++

			return cl.Get(ctx, key, obj, opts...)
		},
		SubResourcePatch: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			requests++

			return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}, pb)

	cached := stored(t, c)
	requests = 0

	require.NoError(t, sut.Track(t.Context(), cached, "pod-x"))
	require.Zero(t, requests)

	// Without the finalizer, it gets added.
	require.NoError(t, util.RemoveFinalizer(t.Context(), c, cached, testFinalizer))
	require.NoError(t, sut.Track(t.Context(), stored(t, c), "pod-x"))
	require.Contains(t, stored(t, c).Finalizers, testFinalizer)
	require.NotContains(t, stored(t, c).Status.ActiveWorkloads, "pod-x")
}

func TestPodRequests(t *testing.T) {
	t.Parallel()

	require.Empty(t, PodRequests(nil))
	require.Equal(t, []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "a"}},
		{NamespacedName: types.NamespacedName{Namespace: "other", Name: "b"}},
	}, PodRequests([]string{"ns/a", "malformed", "other/b"}))
}

// A pod deleted, completed or changed before the cache got the write which
// tracked it used to keep its workload and the finalizer, because only objects
// entering the cache reconciled their workloads. Pods which still use the
// object are not reconciled, as the write which tracks them would reconcile
// them again otherwise.
func TestWorkloadsHandler(t *testing.T) {
	t.Parallel()

	pod := func(name string, using bool, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "ns",
				Labels:    map[string]string{"uses": strconv.FormatBool(using)},
			},
			Status: corev1.PodStatus{Phase: phase},
		}
	}
	pods := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(
			pod("a", true, corev1.PodRunning),
			pod("d", true, corev1.PodRunning),
			pod("e", true, corev1.PodSucceeded),
			pod("f", false, corev1.PodRunning),
		).
		Build()

	sut := WorkloadsHandler(
		pods,
		func(_ context.Context, obj client.Object) []reconcile.Request {
			pb, ok := obj.(*profilebindingapi.ProfileBinding)
			if !ok {
				return nil
			}

			return PodRequests(pb.Status.ActiveWorkloads)
		},
		// The webhook admitted the tracked pod a and pod g, which the
		// binding does not track yet.
		func(context.Context, client.Object) []reconcile.Request {
			return PodRequests([]string{"ns/a", "ns/g"})
		},
		func(obj client.Object, pod *corev1.Pod) bool {
			_, ok := obj.(*profilebindingapi.ProfileBinding)

			return ok && pod.Labels["uses"] == "true"
		},
	)

	q := workqueue.NewTypedRateLimitingQueue(
		workqueue.DefaultTypedControllerRateLimiter[reconcile.Request](),
	)
	t.Cleanup(q.ShutDown)

	drain := func() []string {
		var got []string

		for q.Len() > 0 {
			request, _ := q.Get()
			got = append(got, request.String())
			q.Done(request)
			q.Forget(request)
		}

		slices.Sort(got)

		return got
	}

	oldBinding := testBinding()
	oldBinding.Status.ActiveWorkloads = []string{"ns/a", "ns/b"}

	sut.Create(t.Context(), event.CreateEvent{Object: oldBinding}, q)
	require.Equal(t, []string{"ns/b", "ns/g"}, drain())

	newBinding := oldBinding.DeepCopy()
	newBinding.Status.ActiveWorkloads = []string{"ns/b", "ns/c", "ns/d", "ns/e", "ns/f"}

	// The completed pod and the one which does not use the binding anymore
	// get reconciled as well as the missing one.
	sut.Update(t.Context(), event.UpdateEvent{ObjectOld: oldBinding, ObjectNew: newBinding}, q)
	require.Equal(t, []string{"ns/c", "ns/e", "ns/f"}, drain())

	sut.Delete(t.Context(), event.DeleteEvent{Object: newBinding}, q)
	require.Empty(t, drain())
}

func TestIndexedPods(t *testing.T) {
	t.Parallel()

	const key = "index"

	pod := func(namespace, name, value string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace, Annotations: map[string]string{key: value},
		}}
	}

	pods := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(pod("ns", "a", "binding"), pod("ns", "b", "other"), pod("other", "c", "binding")).
		WithIndex(&corev1.Pod{}, key, func(obj client.Object) []string {
			return []string{obj.GetAnnotations()[key]}
		}).
		Build()

	// Only the pods in the namespace of the object count.
	requests := IndexedPods(pods, key, logr.Discard())(t.Context(), testBinding())
	require.Equal(t, PodRequests([]string{"ns/a"}), requests)
}
