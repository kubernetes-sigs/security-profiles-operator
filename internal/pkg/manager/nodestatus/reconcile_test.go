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
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/common"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	testNamespace   = "test-namespace"
	testProfileName = "test-profile"
	operatorNS      = "security-profiles-operator"
)

// The status label value, as the daemon derives it from the profile kind.
var testProfLabel = "SeccompProfile-" + testProfileName

func reconcileScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, appsv1.AddToScheme(s))
	require.NoError(t, seccompprofileapi.AddToScheme(s))
	require.NoError(t, secprofnodestatusapi.AddToScheme(s))

	return s
}

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

	scheme := reconcileScheme(t)

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
		client: c,
		reader: c,
		log:    logr.Discard(),
		record: rec,
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

func storedProfile(t *testing.T, c client.Client) *seccompprofileapi.SeccompProfile {
	t.Helper()

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, c.Get(
		context.Background(), util.NamespacedName(testProfileName, testNamespace), sp,
	))

	return sp
}

func requireEvent(t *testing.T, rec *events.FakeRecorder, want string) {
	t.Helper()

	select {
	case got := <-rec.Events:
		require.Equal(t, want, got)
	default:
		t.Fatalf("expected event %q, got none", want)
	}
}

func requireNoEvent(t *testing.T, rec *events.FakeRecorder) {
	t.Helper()

	select {
	case got := <-rec.Events:
		t.Fatalf("expected no event, got %q", got)
	default:
	}
}

func TestReconcileMissingStatusIsIgnored(t *testing.T) {
	t.Parallel()

	r, _, rec := newTestReconciler(t)

	res, err := reconcileStatus(t, r, testNodeStatus("worker-1", ""))
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	requireNoEvent(t, rec)
}

func TestReconcileOwnerErrors(t *testing.T) {
	t.Parallel()

	noOwner := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	noOwner.OwnerReferences = nil

	unknownKind := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	unknownKind.OwnerReferences[0].Kind = "Pod"

	cases := []struct {
		name    string
		status  *secprofnodestatusapi.SecurityProfileNodeStatus
		wantErr error
		wantMsg string
	}{
		{
			name:    "NoOwner",
			status:  noOwner,
			wantErr: ErrNoOwnerProfile,
		},
		{
			name:    "UnknownOwnerKind",
			status:  unknownKind,
			wantErr: ErrUnknownOwnerKind,
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
			require.Error(t, err)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.ErrorContains(t, err, tc.wantMsg)
			}

			requireEvent(t, rec, "Warning ReconcileError "+err.Error())
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
			r, c, _ := newTestReconciler(t, testProfile(""), status)

			res, err := reconcileStatus(t, r, status)
			require.NoError(t, err)
			require.Equal(t, reconcile.Result{}, res)

			sp := storedProfile(t, c)
			require.Equal(t, tc.wantStatus, sp.Status.Status)
			require.NotEmpty(t, sp.Status.Conditions)
		})
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, c, rec := newTestReconciler(
				t, testProfile(secprofnodestatusapi.ProfileStatePending), tc.status,
			)

			res, err := reconcileStatus(t, r, tc.status)
			require.NoError(t, err)
			require.Equal(t, reconcile.Result{}, res)
			requireEvent(t, rec, tc.wantEvent)

			// The profile status stays untouched.
			require.Equal(t,
				secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status,
			)
		})
	}
}

// The daemon set lookup needs the operator namespace from the environment, so
// these cases cannot run in parallel.
func TestReconcileWaitsForDaemonSet(t *testing.T) {
	t.Setenv(config.OperatorNamespaceEnvKey, operatorNS)

	status := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	profile := testProfile(secprofnodestatusapi.ProfileStatePending)

	//nolint:paralleltest // the parent test sets the environment
	t.Run("Missing", func(t *testing.T) {
		r, _, _ := newTestReconciler(t, profile.DeepCopy(), status.DeepCopy())

		_, err := reconcileStatus(t, r, status)
		require.ErrorContains(t, err, "cannot get the DS")
	})

	//nolint:paralleltest // the parent test sets the environment
	t.Run("NotReady", func(t *testing.T) {
		r, c, _ := newTestReconciler(t, profile.DeepCopy(), status.DeepCopy(), spodDS(2, 1))

		res, err := reconcileStatus(t, r, status)
		require.NoError(t, err)
		require.Equal(t, dsWait, res.RequeueAfter)
		require.Equal(t,
			secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status,
		)
	})

	//nolint:paralleltest // the parent test sets the environment
	t.Run("NotAllStatusesReported", func(t *testing.T) {
		r, c, _ := newTestReconciler(t, profile.DeepCopy(), status.DeepCopy(), spodDS(2, 2))

		res, err := reconcileStatus(t, r, status)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res)
		require.Equal(t,
			secprofnodestatusapi.ProfileStatePending, storedProfile(t, c).Status.Status,
		)
	})
}

func TestReconcileRemovesStatusOfDeletedNode(t *testing.T) {
	t.Setenv(config.OperatorNamespaceEnvKey, operatorNS)

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

func TestRemoveStatusForDeletedNodeKeepsLiveNodes(t *testing.T) {
	t.Parallel()

	live := testNodeStatus("worker-1", secprofnodestatusapi.ProfileStateInstalled)
	r, c, _ := newTestReconciler(t, live, testNode("worker-1"))

	list := &secprofnodestatusapi.SecurityProfileNodeStatusList{
		Items: []secprofnodestatusapi.SecurityProfileNodeStatus{*live},
	}

	nodeName, err := r.removeStatusForDeletedNode(context.Background(), list, logr.Discard())
	require.NoError(t, err)
	require.Empty(t, nodeName)

	require.NoError(t, c.Get(
		context.Background(), client.ObjectKeyFromObject(live),
		&secprofnodestatusapi.SecurityProfileNodeStatus{},
	))
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

			require.NoError(t, r.reconcileStatus(
				context.Background(), testProfile(""), tc.state, logr.Discard(),
			))

			sp := storedProfile(t, c)
			require.Equal(t, tc.wantStatus, sp.Status.Status)

			ready := sp.Status.GetReadyCondition()
			require.Equal(t, string(tc.wantReason), ready.Reason)
		})
	}
}

func TestUpdateProfileStatusSkipsUnchangedStatus(t *testing.T) {
	t.Parallel()

	r, c, _ := newTestReconciler(t, testProfile(""))
	ctx := context.Background()

	require.NoError(t, r.reconcileStatus(
		ctx, testProfile(""), secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))

	version := storedProfile(t, c).ResourceVersion

	require.NoError(t, r.reconcileStatus(
		ctx, testProfile(""), secprofnodestatusapi.ProfileStateInstalled, logr.Discard(),
	))
	require.Equal(t, version, storedProfile(t, c).ResourceVersion)
}

func TestReconcileStatusOfDeletedProfile(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestReconciler(t)

	// A profile that is gone in the meantime is not an error.
	require.NoError(t, r.reconcileStatus(
		context.Background(),
		testProfile(""),
		secprofnodestatusapi.ProfileStateInstalled,
		logr.Discard(),
	))
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
