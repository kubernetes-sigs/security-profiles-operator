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
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
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
	c := withIndexes(fake.NewClientBuilder().WithScheme(scheme)).
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

// withIndexes adds the field indexes of the manager to the fake client, which
// needs its scheme already.
func withIndexes(b *fake.ClientBuilder) *fake.ClientBuilder {
	for _, index := range fieldIndexes() {
		b = b.WithIndex(index.obj, index.field, index.extract)
	}

	return b
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
	_, err := r.reconcileStatus(ctx, prof, aggregation{state: state}, l)

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

			res, err := reconcileStatus(t, r, status)
			require.NoError(t, err)
			require.Equal(t, dsWait, res.RequeueAfter)

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
		"profile failed to install on nodes worker-2, the status.message of the "+
			"SecurityProfileNodeStatus objects with the spo.x-k8s.io/profile-id label "+
			"of the profile tells why",
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

func TestUnavailableMessage(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		agg  aggregation
		want string
	}{
		{agg: aggregation{}, want: ""},
		{
			agg:  aggregation{unavailableNodes: []string{"a"}},
			want: "the SPOd pod is not available on nodes a, which the state leaves out",
		},
		{
			agg: aggregation{
				unavailableNodes:   []string{"a", "b", "c", "d", "e", "f"},
				unnamedUnavailable: 2,
			},
			want: "the SPOd pod is not available on nodes a, b, c, d, e and 3 more, " +
				"which the state leaves out",
		},
		{
			agg:  aggregation{unnamedUnavailable: 1},
			want: "the SPOd pod is not available on 1 node, which the state leaves out",
		},
		{
			agg:  aggregation{unnamedUnavailable: 2},
			want: "the SPOd pod is not available on 2 nodes, which the state leaves out",
		},
	} {
		require.Equal(t, tc.want, tc.agg.unavailableMessage())
	}
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

		res, err := reconcileStatus(t, r, status)
		require.NoError(t, err)
		require.Equal(t, dsWait, res.RequeueAfter)
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

		// The missing status usually triggers the next reconcile, but the
		// profile is checked again in any case.
		res, err := reconcileStatus(t, r, status)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{RequeueAfter: dsWait}, res)
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
	failPatch := true
	c := withIndexes(fake.NewClientBuilder().WithScheme(scheme)).
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
			Patch: func(
				ctx context.Context, c client.WithWatch, obj client.Object,
				patch client.Patch, opts ...client.PatchOption,
			) error {
				if _, ok := obj.(*seccompprofileapi.SeccompProfile); ok && failPatch {
					return errors.New("patch failed")
				}

				return c.Patch(ctx, obj, patch, opts...)
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

	failPatch = false

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
		name           string
		generation     int64
		status         appsv1.DaemonSetStatus
		wantReady      bool
		wantUpdating   bool
		wantRollingOut bool
	}{
		{
			name:           "NothingScheduled",
			wantRollingOut: true,
		},
		{
			name:           "AllAvailable",
			status:         appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 3},
			wantReady:      true,
			wantRollingOut: true,
		},
		{
			name:           "SomeUnavailable",
			status:         appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberAvailable: 2},
			wantRollingOut: true,
		},
		{
			name: "RollingOut",
			status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3, NumberAvailable: 3, UpdatedNumberScheduled: 1,
			},
			wantReady:      true,
			wantUpdating:   true,
			wantRollingOut: true,
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
			name:       "SpecNotObserved",
			generation: 2,
			status: appsv1.DaemonSetStatus{
				ObservedGeneration:     1,
				DesiredNumberScheduled: 3, NumberAvailable: 2,
				UpdatedNumberScheduled: 3, NumberUnavailable: 1,
			},
			wantUpdating:   true,
			wantRollingOut: true,
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
			ds.Generation = tc.generation
			require.Equal(t, tc.wantReady, daemonSetIsReady(ds))
			require.Equal(t, tc.wantUpdating, daemonSetIsUpdating(ds))
			require.Equal(t, tc.wantRollingOut, daemonSetIsRollingOut(ds))
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

// readySpodPod returns a SPOd pod which is ready since the provided time.
func readySpodPod(node string, since time.Time) *corev1.Pod {
	pod := spodPod(node)
	pod.Status.Conditions = []corev1.PodCondition{{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(since),
	}}

	return pod
}

// degradedSpodDS returns a SPOd DaemonSet which runs its current pods on all
// of three nodes, but not all of them are available.
func degradedSpodDS(available int32) *appsv1.DaemonSet {
	const desired = 3

	ds := selectingSpodDS(desired, available)
	ds.Status.NumberUnavailable = desired - available

	return ds
}

// The SPOd pod on a node which is not ready keeps the DaemonSet from getting
// available. The profile gets the state of the other nodes, and its Ready
// condition names the node which it leaves out.
func TestReconcileAggregatesAvailableNodes(t *testing.T) {
	t.Parallel()

	ready := time.Now().Add(-time.Hour)
	first := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	second := testNodeStatus("worker-2", secprofnodestatusapi.ProfileStateInstalled)
	notReady := testNodeStatus("worker-3", secprofnodestatusapi.ProfileStatePending)
	profile := testProfile(
		secprofnodestatusapi.ProfileStatePending,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
		util.GetFinalizerNodeString("worker-3"),
	)

	r, c, rec := newTestReconciler(t,
		profile, first, second, notReady, degradedSpodDS(2),
		testNode("worker-1"), testNode("worker-2"), testNode("worker-3"),
		readySpodPod("worker-1", ready), readySpodPod("worker-2", ready), spodPod("worker-3"),
	)

	res, err := reconcileStatus(t, r, first)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: dsWait}, res)

	sp := storedProfile(t, c)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, sp.Status.Status)

	// The profile may be missing on the node which is left out, which a
	// distinct reason and a warning event tell.
	cond := sp.Status.GetReadyCondition()
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, string(profilebaseapi.ReasonInstalledOnAvailableNodes), cond.Reason)
	require.Equal(t,
		"the SPOd pod is not available on nodes worker-3, which the state leaves out",
		cond.Message,
	)

	require.Len(t, rec.Events, 1)
	warning := <-rec.Events
	require.Contains(t, warning, "Warning "+string(profilebaseapi.ReasonInstalledOnAvailableNodes))
	require.Contains(t, warning, "nodes worker-3")

	// The requeue does not repeat the event.
	_, err = reconcileStatus(t, r, first)
	require.NoError(t, err)
	require.Empty(t, rec.Events)

	// Another unavailable node gets reported.
	require.NoError(t, c.Delete(context.Background(), spodPod("worker-2")))
	require.NoError(t, c.Create(context.Background(), spodPod("worker-2")))

	_, err = reconcileStatus(t, r, first)
	require.NoError(t, err)
	require.Len(t, rec.Events, 1)
	require.Contains(t, <-rec.Events, "nodes worker-2, worker-3")

	// The node which is not ready keeps its status and finalizer.
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(notReady),
		&secprofnodestatusapi.SecurityProfileNodeStatus{}))
	require.Len(t, storedProfile(t, c).Finalizers, 3)
}

func TestReconcileAggregatesAvailableNodesRules(t *testing.T) {
	t.Parallel()

	ready := time.Now().Add(-time.Hour)

	for name, tc := range map[string]struct {
		ds          *appsv1.DaemonSet
		objs        []client.Object
		wantState   secprofnodestatusapi.ProfileState
		wantMessage string
	}{
		"an available node without status is waited for": {
			ds: degradedSpodDS(2),
			objs: []client.Object{
				readySpodPod("worker-1", ready), readySpodPod("worker-2", ready),
				spodPod("worker-3"),
			},
			wantState: secprofnodestatusapi.ProfileStatePending,
		},
		"a pod which is not ready for long enough is not available": {
			ds: func() *appsv1.DaemonSet {
				ds := degradedSpodDS(1)
				ds.Spec.MinReadySeconds = 3600

				return ds
			}(),
			objs: []client.Object{
				readySpodPod("worker-1", time.Now().Add(-2*time.Hour)),
				readySpodPod("worker-2", time.Now()),
				spodPod("worker-3"),
			},
			wantState: secprofnodestatusapi.ProfileStateInstalled,
			wantMessage: "the SPOd pod is not available on nodes worker-2, worker-3, " +
				"which the state leaves out",
		},
		"a node without pod is counted": {
			ds: degradedSpodDS(1),
			objs: []client.Object{
				readySpodPod("worker-1", ready), spodPod("worker-3"),
			},
			wantState: secprofnodestatusapi.ProfileStateInstalled,
			wantMessage: "the SPOd pod is not available on nodes worker-3 and 1 more, " +
				"which the state leaves out",
		},
		"a rollout is waited for": {
			ds: func() *appsv1.DaemonSet {
				ds := degradedSpodDS(2)
				ds.Status.UpdatedNumberScheduled = 2

				return ds
			}(),
			objs: []client.Object{
				readySpodPod("worker-1", ready), readySpodPod("worker-2", ready),
				spodPod("worker-3"),
			},
			wantState: secprofnodestatusapi.ProfileStatePending,
		},
		"no available pod is waited for": {
			ds: degradedSpodDS(0),
			objs: []client.Object{
				spodPod("worker-1"), spodPod("worker-2"), spodPod("worker-3"),
			},
			wantState: secprofnodestatusapi.ProfileStatePending,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			first := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
			third := testNodeStatus("worker-3", secprofnodestatusapi.ProfileStateError)

			objs := append([]client.Object{
				testProfile(secprofnodestatusapi.ProfileStatePending), first, third, tc.ds,
				testNode("worker-1"), testNode("worker-2"), testNode("worker-3"),
			}, tc.objs...)
			r, c, _ := newTestReconciler(t, objs...)

			res, err := reconcileStatus(t, r, first)
			require.NoError(t, err)
			require.Equal(t, reconcile.Result{RequeueAfter: dsWait}, res)

			sp := storedProfile(t, c)
			require.Equal(t, tc.wantState, sp.Status.Status)

			if tc.wantMessage != "" {
				require.Equal(t, tc.wantMessage, sp.Status.GetReadyCondition().Message)
			}
		})
	}
}

func TestAvailableSpodNodes(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ds := selectingSpodDS(4, 4)
	ds.Spec.MinReadySeconds = 10

	terminating := readySpodPod("terminating", now.Add(-time.Minute))
	deleted := metav1.NewTime(now)
	terminating.DeletionTimestamp = &deleted

	notReady := readySpodPod("not-ready", now.Add(-time.Minute))
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse

	pods := []corev1.Pod{
		*readySpodPod("available", now.Add(-time.Minute)),
		*readySpodPod("too-young", now.Add(-time.Second)),
		*terminating,
		*notReady,
		*spodPod(""),
	}

	require.Equal(t,
		map[string]bool{"available": true},
		availableSpodNodes(ds, pods, now),
	)
}

// Without the SPOd DaemonSet no daemon removes its finalizer, so a profile
// which is being deleted loses all node finalizers.
func TestReconcileDeletingProfileWithoutDaemonSet(t *testing.T) {
	t.Parallel()

	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
		util.HasActivePodsFinalizerString,
	)
	now := metav1.Now()
	profile.DeletionTimestamp = &now

	r, c, _ := newTestReconciler(t, profile, testNode("worker-1"))

	res, err := r.Reconcile(context.Background(),
		profileRequest("SeccompProfile", testNamespace, testProfileName))
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, []string{util.HasActivePodsFinalizerString}, storedProfile(t, c).Finalizers)
}

// The finalizer of a deleted node does not depend on the SPOd DaemonSet, so
// it is removed even if the DaemonSet cannot be read.
func TestReconcileDeletingProfileRemovesDeletedNodeFirst(t *testing.T) {
	t.Parallel()

	profile := testProfile(
		secprofnodestatusapi.ProfileStateInstalled,
		util.GetFinalizerNodeString("worker-1"),
		util.GetFinalizerNodeString("worker-2"),
	)
	now := metav1.Now()
	profile.DeletionTimestamp = &now

	scheme := utiltest.NewScheme(t)
	c := withIndexes(fake.NewClientBuilder().WithScheme(scheme)).
		WithObjects(profile, selectingSpodDS(1, 1), testNode("worker-1"), spodPod("worker-1")).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				if _, ok := obj.(*appsv1.DaemonSet); ok {
					return errors.New("cannot read the DaemonSet")
				}

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	r := &StatusReconciler{
		client: c, reader: c, log: logr.Discard(), record: events.NewFakeRecorder(10),
		namespace: operatorNS,
	}

	_, err := r.Reconcile(context.Background(),
		profileRequest("SeccompProfile", testNamespace, testProfileName))
	require.ErrorContains(t, err, "cannot get the DS")
	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-1")},
		storedProfile(t, c).Finalizers,
	)
}

// With a foreground deletion, the garbage collector deletes the node statuses
// before the profile. The finalizer of a node whose daemon is gone stays, and
// deleting the node later has to reconcile the profile without any status.
func TestDeletedNodeRequestsForDeletingProfile(t *testing.T) {
	t.Parallel()

	deleting := testProfile(
		secprofnodestatusapi.ProfileStateTerminating,
		util.GetFinalizerNodeString("worker-2"),
		metav1.FinalizerDeleteDependents,
	)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now

	live := testProfile(
		secprofnodestatusapi.ProfileStateInstalled, util.GetFinalizerNodeString("worker-2"),
	)
	live.Name = "live-profile"

	r, c, _ := newTestReconciler(t, deleting, live, testNode("worker-1"))

	requests := r.deletedNodeRequests(context.Background(), testNode("worker-2"))
	require.Equal(t,
		[]reconcile.Request{profileRequest("SeccompProfile", testNamespace, testProfileName)},
		requests,
	)
	require.Empty(t, r.deletedNodeRequests(context.Background(), testNode("worker-3")))

	// The request removes the finalizer of the deleted node.
	_, err := r.Reconcile(context.Background(), requests[0])
	require.NoError(t, err)
	require.Equal(t,
		[]string{metav1.FinalizerDeleteDependents},
		storedProfile(t, c).Finalizers,
	)
}

func TestFieldIndexes(t *testing.T) {
	t.Parallel()

	status := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	require.Equal(t, []string{testProfLabel},
		labelIndex(secprofnodestatusapi.StatusToProfLabel)(status))
	require.Equal(t, []string{"worker-1"},
		labelIndex(secprofnodestatusapi.StatusToNodeLabel)(status))
	require.Empty(t, labelIndex("absent")(status))

	profile := testProfile("",
		util.GetFinalizerNodeString("worker-1"), util.HasActivePodsFinalizerString,
	)
	require.Empty(t, deletingProfileNodeFinalizers(profile),
		"a profile which is not being deleted is not indexed")

	now := metav1.Now()
	profile.DeletionTimestamp = &now
	require.Equal(t,
		[]string{util.GetFinalizerNodeString("worker-1")},
		deletingProfileNodeFinalizers(profile),
	)

	// Every kind of profile is indexed.
	kinds := map[string]bool{}

	for _, index := range fieldIndexes() {
		if index.field == deletingProfileNodeFinalizerIndex {
			gvk, err := apiutil.GVKForObject(index.obj, utiltest.NewScheme(t))
			require.NoError(t, err)

			kinds[gvk.Kind] = true
		}
	}

	require.Len(t, kinds, len(profileKinds))
}
