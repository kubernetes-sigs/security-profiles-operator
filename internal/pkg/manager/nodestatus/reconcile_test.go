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

package nodestatus

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/common"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const (
	testNamespace   = "test-namespace"
	testProfileName = "test-profile"
	operatorNS      = "security-profiles-operator"
)

// The status label value, as the daemon derives it from the profile kind.
var testProfLabel = "SeccompProfile-" + testProfileName

func testProfile(
	state secprofnodestatusapi.ProfileState,
	finalizers ...string,
) *seccompprofileapi.SeccompProfile {
	sp := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testProfileName,
			Namespace:  testNamespace,
			UID:        "profile-uid",
			Finalizers: finalizers,
		},
	}
	sp.Status.Status = state

	return sp
}

func testNodeStatus(
	node string, state secprofnodestatusapi.ProfileState,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	return &secprofnodestatusapi.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "seccompprofile-" + testProfileName + "-" + node,
			Namespace: testNamespace,
			Labels: map[string]string{
				secprofnodestatusapi.StatusToProfLabel: testProfLabel,
				secprofnodestatusapi.StatusToNodeLabel: node,
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: seccompprofileapi.GroupVersion.String(),
				Kind:       "SeccompProfile",
				Name:       testProfileName,
				UID:        "profile-uid",
				Controller: new(true),
			}},
		},
		Spec:   secprofnodestatusapi.SecurityProfileNodeStatusSpec{NodeName: node},
		Status: secprofnodestatusapi.SecurityProfileNodeStatusStatus{Status: state},
	}
}

func spodDS(desired, available int32) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "spod", Namespace: operatorNS},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: desired,
			NumberAvailable:        available,
		},
	}
}

func testNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func newTestReconciler(
	t *testing.T, objs ...client.Object,
) (*StatusReconciler, client.Client, *events.FakeRecorder) {
	t.Helper()

	scheme := utiltest.NewScheme(t)

	// Like the cache backed client of the manager, return objects with their
	// type meta set. The reconciler compares the kind based profile name with
	// the status label.
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&seccompprofileapi.SeccompProfile{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context,
				c client.WithWatch,
				key client.ObjectKey,
				obj client.Object,
				opts ...client.GetOption,
			) error {
				if err := c.Get(ctx, key, obj, opts...); err != nil {
					return err
				}

				gvk, err := apiutil.GVKForObject(obj, scheme)
				if err != nil {
					return err
				}

				obj.GetObjectKind().SetGroupVersionKind(gvk)

				return nil
			},
		}).
		Build()
	rec := events.NewFakeRecorder(10)

	return &StatusReconciler{
		client:    c,
		reader:    c,
		log:       logr.Discard(),
		record:    rec,
		namespace: operatorNS,
	}, c, rec
}

func reconcileStatus(
	t *testing.T, r *StatusReconciler, status *secprofnodestatusapi.SecurityProfileNodeStatus,
) (reconcile.Result, error) {
	t.Helper()

	return r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: util.NamespacedName(status.Name, status.Namespace),
	})
}

// setProfileStatus sets the state on the profile without naming failed nodes.
func setProfileStatus(
	r *StatusReconciler,
	ctx context.Context,
	prof *seccompprofileapi.SeccompProfile,
	state secprofnodestatusapi.ProfileState,
	l logr.Logger,
) error {
	_, err := r.reconcileStatus(ctx, prof, state, nil, l)

	return err
}

func storedProfile(t *testing.T, c client.Client) *seccompprofileapi.SeccompProfile {
	t.Helper()

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, c.Get(
		context.Background(), util.NamespacedName(testProfileName, testNamespace), sp,
	))

	return sp
}

func TestReconcileMissingStatusIsIgnored(t *testing.T) {
	t.Parallel()

	r, _, rec := newTestReconciler(t)

	res, err := reconcileStatus(t, r, testNodeStatus("worker-1", ""))
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	utiltest.RequireNoEvent(t, rec)
}

func TestReconcileOwnerErrors(t *testing.T) {
	t.Parallel()

	noOwner := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	noOwner.OwnerReferences = nil

	unknownKind := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	unknownKind.OwnerReferences[0].Kind = "Pod"

	cases := []struct {
		name      string
		status    *secprofnodestatusapi.SecurityProfileNodeStatus
		wantEvent error
		wantMsg   string
	}{
		{
			// A retry cannot find an owner, so the status is only reported.
			name:      "NoOwner",
			status:    noOwner,
			wantEvent: ErrNoOwnerProfile,
		},
		{
			name:      "UnknownOwnerKind",
			status:    unknownKind,
			wantEvent: ErrUnknownOwnerKind,
		},
		{
			name:    "OwnerNotFound",
			status:  testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled),
			wantMsg: "not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, _, rec := newTestReconciler(t, tc.status)

			_, err := reconcileStatus(t, r, tc.status)

			if tc.wantEvent != nil {
				require.NoError(t, err)
				utiltest.RequireEvent(t, rec,
					"Warning ReconcileError getting owner profile: "+tc.wantEvent.Error())

				return
			}

			require.ErrorContains(t, err, tc.wantMsg)
			utiltest.RequireEvent(t, rec, "Warning ReconcileError "+err.Error())
		})
	}
}

func TestReconcileInitializesProfileStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		nodeState  secprofnodestatusapi.ProfileState
		wantStatus secprofnodestatusapi.ProfileState
	}{
		{
			name:       "FromNodeStatus",
			nodeState:  secprofnodestatusapi.ProfileStateInstalled,
			wantStatus: secprofnodestatusapi.ProfileStateInstalled,
		},
		{
			name:       "PendingWithoutNodeStatus",
			nodeState:  "",
			wantStatus: secprofnodestatusapi.ProfileStatePending,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status := testNodeStatus("worker-1", tc.nodeState)

			// Without a SPOd DaemonSet the aggregation cannot run, but the
			// profile gets its initial status anyway.
			r, c, _ := newTestReconciler(t, testProfile(""), status)

			_, err := reconcileStatus(t, r, status)
			require.ErrorContains(t, err, "cannot get the DS")

			sp := storedProfile(t, c)
			require.Equal(t, tc.wantStatus, sp.Status.Status)
			require.NotEmpty(t, sp.Status.Conditions)
		})
	}
}

// The initialization of the profile status takes the state of a single node.
// The aggregation of all node statuses follows in the same reconcile, nothing
// else would requeue the profile.
func TestReconcileInitializationAggregatesAllNodes(t *testing.T) {
	t.Parallel()

	installed := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	pending := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStatePending)

	r, c, _ := newTestReconciler(t,
		testProfile(""), installed, pending, spodDS(2, 2),
		testNode("worker-1"), testNode("worker-2"),
	)

	res, err := reconcileStatus(t, r, installed)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t,
		secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status,
	)
}

func TestReconcileErrorConditionNamesFailedNodes(t *testing.T) {
	t.Parallel()

	ok := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	failed := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateError)

	r, c, _ := newTestReconciler(t,
		testProfile(secprofnodestatusapi.ProfileStatePending), ok, failed, spodDS(2, 2),
		testNode("worker-1"), testNode("worker-2"),
	)

	_, err := reconcileStatus(t, r, ok)
	require.NoError(t, err)

	sp := storedProfile(t, c)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, sp.Status.Status)
	require.Equal(t,
		"profile failed to install on nodes worker-2, "+
			"see the SecurityProfileNodeStatus objects of the profile for details",
		sp.Status.GetReadyCondition().Message,
	)
}

func TestErrorConditionMessage(t *testing.T) {
	t.Parallel()

	require.Contains(t, errorConditionMessage(nil), "one or more nodes")
	require.Contains(t,
		errorConditionMessage([]string{"a", "b", "c", "d", "e", "f", "g"}),
		"nodes a, b, c, d, e and 2 more,",
	)
}

func TestReconcileSkipsMislabeledStatus(t *testing.T) {
	t.Parallel()

	unlabeled := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	delete(unlabeled.Labels, secprofnodestatusapi.StatusToProfLabel)

	foreign := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	foreign.Labels[secprofnodestatusapi.StatusToProfLabel] = "SeccompProfile-other"

	cases := []struct {
		name      string
		status    *secprofnodestatusapi.SecurityProfileNodeStatus
		wantEvent string
	}{
		{
			name:      "Unlabeled",
			status:    unlabeled,
			wantEvent: "Warning ReconcileError unlabeled node status",
		},
		{
			name:      "DifferentProfile",
			status:    foreign,
			wantEvent: "Warning ReconcileError status doesn't match owner",
		},
	}

	for _, tc := range cases {
		for _, initial := range []secprofnodestatusapi.ProfileState{
			secprofnodestatusapi.ProfileStatePending, "",
		} {
			t.Run(tc.name+"/"+string(initial), func(t *testing.T) {
				t.Parallel()

				r, c, rec := newTestReconciler(t, testProfile(initial), tc.status.DeepCopy())

				res, err := reconcileStatus(t, r, tc.status)
				require.NoError(t, err)
				require.Equal(t, reconcile.Result{}, res)
				utiltest.RequireEvent(t, rec, tc.wantEvent)

				// The profile status stays untouched, it is not seeded from a
				// status which does not belong to it either.
				require.Equal(t, initial, storedProfile(t, c).Status.Status)
			})
		}
	}
}

func TestReconcileWaitsForDaemonSet(t *testing.T) {
	t.Parallel()

	status := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(secprofnodestatusapi.ProfileStatePending)

	t.Run("Missing", func(t *testing.T) {
		t.Parallel()

		r, _, _ := newTestReconciler(t, profile.DeepCopy(), status.DeepCopy())

		_, err := reconcileStatus(t, r, status)
		require.ErrorContains(t, err, "cannot get the DS")
	})

	t.Run("NotReady", func(t *testing.T) {
		t.Parallel()

		r, c, _ := newTestReconciler(t, profile.DeepCopy(), status.DeepCopy(), spodDS(2, 1))

		res, err := reconcileStatus(t, r, status)
		require.NoError(t, err)
		require.Equal(t, dsWait, res.RequeueAfter)
		require.Equal(t,
			secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status,
		)
	})

	t.Run("NotAllStatusesReported", func(t *testing.T) {
		t.Parallel()

		r, c, _ := newTestReconciler(
			t, profile.DeepCopy(), status.DeepCopy(), spodDS(2, 2), testNode("worker-1"),
		)

		res, err := reconcileStatus(t, r, status)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res)
		require.Equal(t,
			secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status,
		)
	})
}

// Right after a node got deleted, the DaemonSet still counts it, so the
// profile is reconciled again later instead of aggregating its status.
func TestReconcileWaitsForDaemonSetToDropDeletedNode(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	gone := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateError)
	profile := testProfile(secprofnodestatusapi.ProfileStatePending)

	r, c, _ := newTestReconciler(t, profile, live, gone, spodDS(2, 2), testNode("worker-1"))

	res, err := reconcileStatus(t, r, live)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: dsWait}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status)
}

func TestReconcileRemovesStatusOfDeletedNode(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	gone := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
	)

	// Only one node is left for the two statuses.
	r, c, _ := newTestReconciler(t, profile, live, gone, spodDS(1, 1), testNode("worker-1"))

	res, err := reconcileStatus(t, r, live)
	require.NoError(t, err)
	require.Equal(t, time.Second, res.RequeueAfter)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	err = c.Get(context.Background(), client.ObjectKeyFromObject(gone), status)
	require.True(t, kerrors.IsNotFound(err))

	err = c.Get(context.Background(), client.ObjectKeyFromObject(live), status)
	require.NoError(t, err)

	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-1")},
		storedProfile(t, c).Finalizers,
	)
}

func TestDeletedNodeRequests(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	gone := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateError)
	r, _, _ := newTestReconciler(t, live, gone)

	requests := r.deletedNodeRequests(context.Background(), testNode("worker-2"))
	require.Equal(t,
		[]reconcile.Request{profileRequest("SeccompProfile", testNamespace, testProfileName)},
		requests,
	)

	require.Empty(t, r.deletedNodeRequests(context.Background(), testNode("worker-3")))
}

func TestStatusesOfDeletedNodesKeepsLiveNodes(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	r, _, _ := newTestReconciler(t, live, testNode("worker-1"))

	list := &secprofnodestatusapi.SecurityProfileNodeStatusList{
		Items: []secprofnodestatusapi.SecurityProfileNodeStatus{*live},
	}

	stale, err := r.statusesOfDeletedNodes(context.Background(), list)
	require.NoError(t, err)
	require.Empty(t, stale)
}

// A failed attempt to remove the finalizer of a deleted node must not lose
// track of it: the finalizer is removed before the status, and later
// reconciliations take the finalizers from the profile itself.
func TestReconcileRemovesFinalizerOfDeletedNodeWithoutStatus(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
		util.HasActivePodsFinalizerString,
	)

	r, c, _ := newTestReconciler(t, profile, live, spodDS(1, 1), testNode("worker-1"))

	res, err := reconcileStatus(t, r, live)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-1"), util.HasActivePodsFinalizerString},
		storedProfile(t, c).Finalizers,
	)
}

func TestRemoveStaleStatusesRemovesFinalizerFirst(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	gone := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
	)

	scheme := utiltest.NewScheme(t)
	failUpdate := true
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(profile, live, gone, spodDS(1, 1), testNode("worker-1")).
		WithStatusSubresource(&seccompprofileapi.SeccompProfile{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				if err := c.Get(ctx, key, obj, opts...); err != nil {
					return err
				}

				gvk, err := apiutil.GVKForObject(obj, scheme)
				if err != nil {
					return err
				}

				obj.GetObjectKind().SetGroupVersionKind(gvk)

				return nil
			},
			Update: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
			) error {
				if _, ok := obj.(*seccompprofileapi.SeccompProfile); ok && failUpdate {
					return errors.New("update failed")
				}

				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()
	r := &StatusReconciler{
		client: c, reader: c, log: logr.Discard(), record: events.NewFakeRecorder(10),
		namespace: operatorNS,
	}

	// The status stays while the finalizer cannot be removed.
	_, err := reconcileStatus(t, r, live)
	require.Error(t, err)
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(gone),
		&secprofnodestatusapi.SecurityProfileNodeStatus{}))
	require.Len(t, storedProfile(t, c).Finalizers, 2)

	failUpdate = false

	_, err = reconcileStatus(t, r, live)
	require.NoError(t, err)

	err = c.Get(context.Background(), client.ObjectKeyFromObject(gone),
		&secprofnodestatusapi.SecurityProfileNodeStatus{})
	require.True(t, kerrors.IsNotFound(err))
	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-1")},
		storedProfile(t, c).Finalizers,
	)
}

func TestReconcileDeletingProfile(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		ds             *appsv1.DaemonSet
		objs           []client.Object
		deleting       bool
		wantFinalizers []string
		wantRequeue    time.Duration
	}{
		"removes finalizer of deleted node": {
			ds:       selectingSpodDS(1, 1),
			objs:     []client.Object{testNode("worker-1"), spodPod("worker-1")},
			deleting: true,
			wantFinalizers: []string{
				util.GetFinalizerNodeString("worker-1"), util.HasActivePodsFinalizerString,
			},
		},
		"removes finalizer of unscheduled node": {
			ds: selectingSpodDS(1, 1),
			objs: []client.Object{
				testNode("worker-1"), testNode("worker-2"), spodPod("worker-1"),
			},
			deleting: true,
			wantFinalizers: []string{
				util.GetFinalizerNodeString("worker-1"), util.HasActivePodsFinalizerString,
			},
		},
		"keeps finalizer of live node while not settled": {
			ds: func() *appsv1.DaemonSet {
				ds := selectingSpodDS(2, 2)
				ds.Status.UpdatedNumberScheduled = 1

				return ds
			}(),
			objs: []client.Object{
				testNode("worker-1"), testNode("worker-2"), spodPod("worker-1"),
			},
			deleting: true,
			wantFinalizers: []string{
				util.GetFinalizerNodeString("worker-1"),
				util.GetFinalizerNodeString("worker-2"),
				util.HasActivePodsFinalizerString,
			},
			wantRequeue: dsWait,
		},
		"ignores profile which is not deleted": {
			ds:   selectingSpodDS(1, 1),
			objs: []client.Object{testNode("worker-1"), spodPod("worker-1")},
			wantFinalizers: []string{
				util.GetFinalizerNodeString("worker-1"),
				util.GetFinalizerNodeString("worker-2"),
				util.HasActivePodsFinalizerString,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			profile := testProfile(
				secprofnodestatusapi.ProfileStateInstalled,
				util.GetFinalizerNodeString("worker-1"),
				util.GetFinalizerNodeString("worker-2"),
				util.HasActivePodsFinalizerString,
			)

			if tc.deleting {
				now := metav1.Now()
				profile.DeletionTimestamp = &now
			}

			r, c, _ := newTestReconciler(t, append(tc.objs, profile, tc.ds)...)

			res, err := r.Reconcile(context.Background(),
				profileRequest("SeccompProfile", testNamespace, testProfileName))
			require.NoError(t, err)
			require.Equal(t, tc.wantRequeue, res.RequeueAfter)
			require.Equal(t, tc.wantFinalizers, storedProfile(t, c).Finalizers)
		})
	}
}

func TestReconcileDeletingProfileNotFound(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestReconciler(t)

	res, err := r.Reconcile(context.Background(),
		profileRequest("SeccompProfile", testNamespace, testProfileName))
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	_, err = r.Reconcile(context.Background(),
		profileRequest("Pod", testNamespace, testProfileName))
	require.ErrorIs(t, err, ErrUnknownOwnerKind)
}

func TestIsNodeFinalizer(t *testing.T) {
	t.Parallel()

	require.True(t, isNodeFinalizer(util.GetFinalizerNodeString("worker-1")))
	require.False(t, isNodeFinalizer(util.HasActivePodsFinalizerString))
	require.False(t, isNodeFinalizer("spo.x-k8s.io/partial-profile-finalizer"))
	require.False(t, isNodeFinalizer("example.com/foo-deleted"))
}

func spodPod(node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "spod-" + node,
			Namespace: operatorNS,
			Labels:    map[string]string{"name": "spod"},
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
}

func selectingSpodDS(desired, available int32) *appsv1.DaemonSet {
	ds := spodDS(desired, available)
	ds.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"name": "spod"}}
	ds.Generation = 2
	ds.Status.ObservedGeneration = 2
	ds.Status.CurrentNumberScheduled = desired
	ds.Status.UpdatedNumberScheduled = desired

	return ds
}

func TestReconcileRemovesStatusOfUnscheduledNode(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	tainted := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
	)

	// Both nodes exist, but only worker-1 still runs a SPOd pod.
	r, c, _ := newTestReconciler(t, profile, live, tainted, selectingSpodDS(1, 1),
		testNode("worker-1"), testNode("worker-2"), spodPod("worker-1"))

	res, err := reconcileStatus(t, r, live)
	require.NoError(t, err)
	require.Equal(t, time.Second, res.RequeueAfter)

	err = c.Get(context.Background(), client.ObjectKeyFromObject(tainted),
		&secprofnodestatusapi.SecurityProfileNodeStatus{})
	require.True(t, kerrors.IsNotFound(err))
	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-1")},
		storedProfile(t, c).Finalizers,
	)
}

func TestReconcileAggregatesWithoutStaleStatus(t *testing.T) {
	t.Parallel()

	first := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	second := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(
		secprofnodestatusapi.ProfileStatePending,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
	)

	// The SPOd pod list is incomplete, so nothing must be removed, but the
	// reconciler must not requeue forever either.
	r, c, _ := newTestReconciler(t, profile, first, second, selectingSpodDS(1, 1),
		testNode("worker-1"), testNode("worker-2"))

	res, err := reconcileStatus(t, r, first)
	require.NoError(t, err)
	require.Equal(t, dsWait, res.RequeueAfter)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, storedProfile(t, c).Status.Status)

	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(second),
		&secprofnodestatusapi.SecurityProfileNodeStatus{}))
	require.Len(t, storedProfile(t, c).Finalizers, 2)
}

func TestListStatusesForProfile(t *testing.T) {
	t.Parallel()

	mine := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)

	otherNamespace := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
	otherNamespace.Namespace = "other"

	otherProfile := testNodeStatus("worker-3", secprofnodestatusapi.ProfileStateInstalled)
	otherProfile.Labels[secprofnodestatusapi.StatusToProfLabel] = "SeccompProfile-other"

	_, c, _ := newTestReconciler(t, mine, otherNamespace, otherProfile)

	list, err := listStatusesForProfile(context.Background(), c, testNamespace, testProfLabel)
	require.NoError(t, err)
	require.Len(t, list.Items, 1)
	require.Equal(t, mine.Name, list.Items[0].Name)
}

func TestUpdateProfileStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		state      secprofnodestatusapi.ProfileState
		wantStatus secprofnodestatusapi.ProfileState
		wantReason common.ConditionReason
	}{
		{"", secprofnodestatusapi.ProfileStatePending, common.ReasonCreating},
		{
			secprofnodestatusapi.ProfileStatePending,
			secprofnodestatusapi.ProfileStatePending,
			common.ReasonCreating,
		},
		{
			secprofnodestatusapi.ProfileStateInProgress,
			secprofnodestatusapi.ProfileStateInProgress,
			common.ReasonCreating,
		},
		{
			secprofnodestatusapi.ProfileStateInstalled,
			secprofnodestatusapi.ProfileStateInstalled,
			common.ReasonAvailable,
		},
		{
			secprofnodestatusapi.ProfileStateTerminating,
			secprofnodestatusapi.ProfileStateTerminating,
			common.ReasonDeleting,
		},
		{
			secprofnodestatusapi.ProfileStateError,
			secprofnodestatusapi.ProfileStateError,
			common.ReasonUnavailable,
		},
		{
			secprofnodestatusapi.ProfileStatePartial,
			secprofnodestatusapi.ProfileStatePartial,
			common.ReasonUnavailable,
		},
		{
			secprofnodestatusapi.ProfileStateDisabled,
			secprofnodestatusapi.ProfileStateDisabled,
			common.ReasonUnavailable,
		},
	}

	for _, tc := range cases {
		t.Run("State"+string(tc.state), func(t *testing.T) {
			t.Parallel()

			r, c, _ := newTestReconciler(t, testProfile(""))

			require.NoError(t, setProfileStatus(r,
				context.Background(), testProfile(""), tc.state, logr.Discard(),
			))

			sp := storedProfile(t, c)
			require.Equal(t, tc.wantStatus, sp.Status.Status)

			ready := sp.Status.GetReadyCondition()
			require.Equal(t, string(tc.wantReason), ready.Reason)
		})
	}
}

func TestUpdateProfileStatusSetsObservedGeneration(t *testing.T) {
	t.Parallel()

	profile := testProfile("")
	profile.Generation = 3
	r, c, _ := newTestReconciler(t, profile)

	require.NoError(t, setProfileStatus(r,
		context.Background(), profile, secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))

	first := storedProfile(t, c).Status.GetReadyCondition()
	require.Equal(t, int64(3), first.ObservedGeneration)

	// A new generation in the same state keeps the transition time.
	sp := storedProfile(t, c)
	sp.Generation = 4
	require.NoError(t, c.Update(context.Background(), sp))

	require.NoError(t, setProfileStatus(r,
		context.Background(), sp, secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))

	second := storedProfile(t, c).Status.GetReadyCondition()
	require.Equal(t, storedProfile(t, c).Generation, second.ObservedGeneration)
	require.Equal(t, first.LastTransitionTime, second.LastTransitionTime)
}

func TestUpdateProfileStatusSkipsUnchangedStatus(t *testing.T) {
	t.Parallel()

	r, c, _ := newTestReconciler(t, testProfile(""))
	ctx := context.Background()

	require.NoError(t, setProfileStatus(r,
		ctx, testProfile(""), secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))

	stored := storedProfile(t, c)

	// The cached profile is up to date, so the API server is not asked.
	r.reader = failingReader{}

	require.NoError(t, setProfileStatus(r,
		ctx, stored, secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))
	require.Equal(t, stored.ResourceVersion, storedProfile(t, c).ResourceVersion)
}

// failingReader is a client.Reader which fails every read.
type failingReader struct{}

func (failingReader) Get(
	context.Context,
	client.ObjectKey,
	client.Object,
	...client.GetOption,
) error {
	return errors.New("unexpected read from the API server")
}

func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("unexpected read from the API server")
}

// An outdated cached profile leads to a conflict, which is resolved by
// reading the profile from the API server.
func TestUpdateProfileStatusOutdatedCache(t *testing.T) {
	t.Parallel()

	r, c, _ := newTestReconciler(t, testProfile(""))
	ctx := context.Background()

	outdated := storedProfile(t, c)

	current := storedProfile(t, c)
	current.Labels = map[string]string{"changed": "true"}
	require.NoError(t, c.Update(ctx, current))

	require.NoError(t, setProfileStatus(r,
		ctx, outdated, secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, storedProfile(t, c).Status.Status)
}

func TestSiblingStatusRequests(t *testing.T) {
	t.Parallel()

	first := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	second := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)

	unlabeled := testNodeStatus("worker-3", secprofnodestatusapi.ProfileStateInstalled)
	delete(unlabeled.Labels, secprofnodestatusapi.StatusToProfLabel)

	r, _, _ := newTestReconciler(t, first, second)
	ctx := context.Background()

	// All statuses of a profile map to the request of the profile.
	for _, status := range []*secprofnodestatusapi.SecurityProfileNodeStatus{first, second} {
		require.Equal(t,
			[]reconcile.Request{profileRequest("SeccompProfile", testNamespace, testProfileName)},
			r.siblingStatusRequests(ctx, status),
		)
	}

	// A status which does not belong to a profile is reconciled on its own.
	require.Equal(t,
		[]reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(unlabeled)}},
		r.siblingStatusRequests(ctx, unlabeled),
	)
}

func TestStatusRequestsForDeletingProfile(t *testing.T) {
	t.Parallel()

	status := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	r, _, _ := newTestReconciler(t, status)

	profile := testProfile("")
	now := metav1.Now()
	profile.DeletionTimestamp = &now

	require.Equal(t,
		[]reconcile.Request{profileRequest("SeccompProfile", testNamespace, testProfileName)},
		r.statusRequests("SeccompProfile")(context.Background(), profile),
	)
}

// A profile request aggregates the node statuses into the profile status.
func TestReconcileProfileRequestAggregatesStatuses(t *testing.T) {
	t.Parallel()

	status := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	r, c, _ := newTestReconciler(t, testProfile(""), status, spodDS(1, 1), testNode("worker-1"))

	_, err := r.Reconcile(context.Background(),
		profileRequest("SeccompProfile", testNamespace, testProfileName))
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, storedProfile(t, c).Status.Status)
}

func TestReconcileStatusOfDeletedProfile(t *testing.T) {
	t.Parallel()

	r, c, rec := newTestReconciler(t)

	// A profile that is gone in the meantime is not an error, and it does not
	// get recreated by the status update.
	require.NoError(t, setProfileStatus(r,
		context.Background(),
		testProfile(""),
		secprofnodestatusapi.ProfileStateInstalled,
		logr.Discard(),
	))

	err := c.Get(context.Background(),
		util.NamespacedName(testProfileName, testNamespace), &seccompprofileapi.SeccompProfile{})
	require.True(t, kerrors.IsNotFound(err))
	utiltest.RequireNoEvent(t, rec)
}

func TestDaemonSetReadiness(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		status       appsv1.DaemonSetStatus
		wantReady    bool
		wantUpdating bool
	}{
		{
			name: "NothingScheduled",
		},
		{
			name:      "AllAvailable",
			status:    appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 3},
			wantReady: true,
		},
		{
			name:   "SomeUnavailable",
			status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 2},
		},
		{
			name: "RollingOut",
			status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3, NumberAvailable: 3, UpdatedNumberScheduled: 1,
			},
			wantReady:    true,
			wantUpdating: true,
		},
		{
			name: "UpdatedButUnavailable",
			status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3, NumberAvailable: 2,
				UpdatedNumberScheduled: 3, NumberUnavailable: 1,
			},
			wantUpdating: true,
		},
		{
			name: "RolledOut",
			status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3, NumberAvailable: 3, UpdatedNumberScheduled: 3,
			},
			wantReady: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ds := &appsv1.DaemonSet{Status: tc.status}
			require.Equal(t, tc.wantReady, daemonSetIsReady(ds))
			require.Equal(t, tc.wantUpdating, daemonSetIsUpdating(ds))
		})
	}
}

// A live node whose SPOd pod is being replaced must keep its status and
// finalizer, even if another node which runs a pod is no longer scheduled.
func TestReconcileKeepsStatusOfNodeWithReplacedPod(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		mutateDS func(*appsv1.DaemonSet)
		pods     []client.Object
	}{
		"terminating pod on the node": {
			pods: func() []client.Object {
				terminating := spodPod("worker-2")
				terminating.Finalizers = []string{"test"}
				now := metav1.Now()
				terminating.DeletionTimestamp = &now

				return []client.Object{spodPod("worker-1"), terminating}
			}(),
		},
		"pod on unscheduled node": {
			mutateDS: func(ds *appsv1.DaemonSet) { ds.Status.NumberMisscheduled = 1 },
			pods:     []client.Object{spodPod("worker-1"), spodPod("worker-3")},
		},
		"status of the daemonset is stale": {
			mutateDS: func(ds *appsv1.DaemonSet) { ds.Generation = 3 },
			pods:     []client.Object{spodPod("worker-1")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			first := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
			second := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
			profile := testProfile(
				secprofnodestatusapi.ProfileStateInstalled,
				util.GetFinalizerNodeString("worker-1"),
				util.GetFinalizerNodeString("worker-2"),
			)

			ds := selectingSpodDS(1, 1)
			if tc.mutateDS != nil {
				tc.mutateDS(ds)
			}

			objs := append([]client.Object{
				profile, first, second, ds,
				testNode("worker-1"), testNode("worker-2"), testNode("worker-3"),
			}, tc.pods...)
			r, c, _ := newTestReconciler(t, objs...)

			res, err := reconcileStatus(t, r, first)
			require.NoError(t, err)
			require.Equal(t, dsWait, res.RequeueAfter)
			require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(second),
				&secprofnodestatusapi.SecurityProfileNodeStatus{}))
			require.Len(t, storedProfile(t, c).Finalizers, 2)
		})
	}
}

// A status without owner, like one created by hand for a node, must not keep
// the profile from being aggregated, even if its name sorts first.
func TestReconcileProfileRequestSkipsUnownedStatus(t *testing.T) {
	t.Parallel()

	unowned := testNodeStatus("a-fake-node", secprofnodestatusapi.ProfileStateInstalled)
	unowned.OwnerReferences = nil
	owned := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)

	r, c, _ := newTestReconciler(
		t, testProfile(""), unowned, owned, spodDS(1, 1), testNode("worker-1"),
	)

	_, err := r.Reconcile(context.Background(),
		profileRequest("SeccompProfile", testNamespace, testProfileName))
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, storedProfile(t, c).Status.Status)
}

func TestStatusRequestsForProfile(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestReconciler(t)

	require.Equal(
		t,
		[]reconcile.Request{profileRequest("SeccompProfile", testNamespace, testProfileName)},
		r.statusRequests("SeccompProfile")(context.Background(), testProfile("")),
	)
}

// The nodes are only needed by name, so they are read as metadata, which
// shares the metadata informer of the SPOD controller instead of caching the
// full node objects.
func TestNodesAreReadAsMetadata(t *testing.T) {
	t.Parallel()

	scheme := utiltest.NewScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testNode("worker-1"), testNode("worker-2")).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				if _, ok := obj.(*corev1.Node); ok {
					return errors.New("full node read")
				}

				return c.Get(ctx, key, obj, opts...)
			},
			List: func(
				ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption,
			) error {
				if _, ok := list.(*corev1.NodeList); ok {
					return errors.New("full node list")
				}

				return c.List(ctx, list, opts...)
			},
		}).
		Build()

	r := &StatusReconciler{client: c, reader: c, log: logr.Discard(), namespace: operatorNS}

	names, err := r.nodeNames(context.Background())
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"worker-1", "worker-2"}, names)

	list := &secprofnodestatusapi.SecurityProfileNodeStatusList{
		Items: []secprofnodestatusapi.SecurityProfileNodeStatus{
			*testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled),
			*testNodeStatus("worker-3", secprofnodestatusapi.ProfileStateInstalled),
		},
	}

	stale, err := r.statusesOfDeletedNodes(context.Background(), list)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	require.Equal(t, "worker-3", stale[0].Spec.NodeName)
}

func TestDeletedNodeFinalizers(t *testing.T) {
	t.Parallel()

	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
		util.HasActivePodsFinalizerString,
	)

	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-2")},
		deletedNodeFinalizers(profile, []string{"worker-1"}),
	)
	require.Empty(t, deletedNodeFinalizers(profile, []string{"worker-1", "worker-2"}))
	require.Len(t, deletedNodeFinalizers(profile, nil), 2,
		"only node finalizers are reported, not the one of the active pods")
}

func TestDeletedNodeFinalizersLongNodeName(t *testing.T) {
	t.Parallel()

	longNode := strings.Repeat("a", 60) + "-worker-1"
	current := util.GetFinalizerNodeString(longNode)
	legacy := util.GetLegacyFinalizerNodeString(longNode)
	require.NotEmpty(t, legacy)
	require.NotEqual(t, current, legacy)
	require.Equal(t, []string{current, legacy}, nodeFinalizers(longNode))
	require.Equal(t, []string{util.GetFinalizerNodeString("worker-1")}, nodeFinalizers("worker-1"))

	profile := testProfile(secprofnodestatusapi.ProfileStateInstalled, current, legacy)

	require.Empty(t, deletedNodeFinalizers(profile, []string{longNode}),
		"the legacy finalizer of an existing node is not stale")
	require.Equal(t, []string{current, legacy}, deletedNodeFinalizers(profile, nil))
}

// TestStaleNodeFinalizersSharedLegacy asserts that the legacy finalizer, which
// nodes with a long common name prefix share, is only removed along with a
// stale node if no remaining node maps to it.
func TestStaleNodeFinalizersSharedLegacy(t *testing.T) {
	t.Parallel()

	nodeA := strings.Repeat("a", 60) + "-worker-1"
	nodeB := strings.Repeat("a", 60) + "-worker-2"
	legacy := util.GetLegacyFinalizerNodeString(nodeA)
	require.Equal(t, legacy, util.GetLegacyFinalizerNodeString(nodeB))

	currentA := util.GetFinalizerNodeString(nodeA)

	// Node B still exists, so the shared legacy finalizer stays.
	require.Equal(t,
		[]string{currentA},
		staleNodeFinalizers([]string{nodeA}, []string{nodeA}, []string{nodeA, nodeB}),
	)

	// Node B is stale as well.
	require.Equal(t,
		[]string{currentA, legacy},
		staleNodeFinalizers([]string{nodeA}, []string{nodeA, nodeB}, []string{nodeA, nodeB}),
	)

	// Node A is gone and nothing else maps to the legacy finalizer.
	require.Equal(t,
		[]string{currentA, legacy},
		staleNodeFinalizers([]string{nodeA}, []string{nodeA}, []string{"worker-3"}),
	)
}

// TestReconcileKeepsSharedLegacyFinalizer asserts that removing the status of
// a deleted node keeps the legacy finalizer which a live node shares.
func TestReconcileKeepsSharedLegacyFinalizer(t *testing.T) {
	t.Parallel()

	nodeA := strings.Repeat("a", 60) + "-worker-1"
	nodeB := strings.Repeat("a", 60) + "-worker-2"
	legacy := util.GetLegacyFinalizerNodeString(nodeA)
	require.Equal(t, legacy, util.GetLegacyFinalizerNodeString(nodeB))

	live := testNodeStatus("live", secprofnodestatusapi.ProfileStateInstalled)
	live.Spec.NodeName = nodeB
	gone := testNodeStatus("gone", secprofnodestatusapi.ProfileStateInstalled)
	gone.Spec.NodeName = nodeA

	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString(nodeA),
		legacy,
	)

	// Node B has not migrated yet, it relies on the legacy finalizer.
	r, c, _ := newTestReconciler(t, profile, live, gone, spodDS(1, 1), testNode(nodeB))

	res, err := reconcileStatus(t, r, live)
	require.NoError(t, err)
	require.Equal(t, time.Second, res.RequeueAfter)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	err = c.Get(context.Background(), client.ObjectKeyFromObject(gone), status)
	require.True(t, kerrors.IsNotFound(err))

	require.Equal(t, []string{legacy}, storedProfile(t, c).Finalizers)
}

func TestNodeStatusChangedPredicate(t *testing.T) {
	t.Parallel()

	p := nodeStatusChanged()
	base := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStatePending)

	update := func(mutate func(*secprofnodestatusapi.SecurityProfileNodeStatus)) bool {
		changed := base.DeepCopy()
		mutate(changed)

		return p.Update(event.UpdateEvent{ObjectOld: base, ObjectNew: changed})
	}

	// The daemon updates the state label before the state itself.
	require.False(t, update(func(s *secprofnodestatusapi.SecurityProfileNodeStatus) {
		s.Labels[secprofnodestatusapi.StatusStateLabel] = "Installed"
	}))
	require.False(t, update(func(s *secprofnodestatusapi.SecurityProfileNodeStatus) {
		s.Annotations = map[string]string{"key": "value"}
	}))
	require.True(t, update(func(s *secprofnodestatusapi.SecurityProfileNodeStatus) {
		s.Status.Status = secprofnodestatusapi.ProfileStateInstalled
	}))
	require.True(t, update(func(s *secprofnodestatusapi.SecurityProfileNodeStatus) {
		s.Labels[secprofnodestatusapi.StatusToProfLabel] = "other"
	}))
	require.True(t, update(func(s *secprofnodestatusapi.SecurityProfileNodeStatus) {
		s.OwnerReferences = nil
	}))
	require.True(t, p.Create(event.CreateEvent{Object: base}))
	require.True(t, p.Delete(event.DeleteEvent{Object: base}))
}
