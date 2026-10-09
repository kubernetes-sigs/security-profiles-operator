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

package common

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const testNodeName = "test-node"

func testProfile(finalizers ...string) *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-profile",
			Namespace:  "default",
			Finalizers: finalizers,
		},
	}
}

func testReasons() DeletionReasons {
	return DeletionReasons{
		CannotUpdateProfile: "CannotUpdate",
		CannotRemoveProfile: "CannotRemove",
		CannotUpdateStatus:  "CannotUpdateStatus",
	}
}

func testNodeStatus(
	t *testing.T, profile *seccompprofileapi.SeccompProfile, cl client.Client,
) *nodestatus.StatusClient {
	t.Helper()

	nsc, err := nodestatus.NewForProfileOnNode(profile, cl, testNodeName)
	require.NoError(t, err)

	return nsc
}

// statusGetFn returns a Get interceptor that reports a node status in the
// provided state and leaves all other objects untouched.
func statusGetFn(state secprofnodestatusapi.ProfileState) func(
	context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption,
) error {
	return utiltest.GetReturns(nil, func(obj client.Object) {
		if ns, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
			ns.Status.Status = state
			ns.Labels = map[string]string{
				secprofnodestatusapi.StatusStateLabel: string(state),
			}
		}
	})
}

func TestReconcileDeletion(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")
	finalizer := util.GetFinalizerNodeString(testNodeName)

	cases := []struct {
		name           string
		profile        *seccompprofileapi.SeccompProfile
		funcs          interceptor.Funcs
		handleDeletion func() (reconcile.Result, error)
		wantResult     reconcile.Result
		wantErr        bool
		wantIncError   bool
		wantHandled    bool
	}{
		{
			name:    "NoFinalizer_NothingToDo",
			profile: testProfile(),
			funcs: interceptor.Funcs{
				Get: utiltest.GetReturns(errors.New("must not be called")),
			},
			wantResult: reconcile.Result{},
		},
		{
			name:    "StatusExistsNotTerminating_SetsTerminatingAndRequeues",
			profile: testProfile(finalizer),
			funcs: interceptor.Funcs{
				Get:              statusGetFn(secprofnodestatusapi.ProfileStatePending),
				Patch:            utiltest.PatchReturns(nil),
				SubResourcePatch: utiltest.SubResourcePatchReturns(nil),
			},
			wantResult: reconcile.Result{RequeueAfter: Wait},
		},
		{
			name:    "StatusExistsTerminating_ActivePodsFinalizer_Requeues",
			profile: testProfile(finalizer, util.HasActivePodsFinalizerString),
			funcs: interceptor.Funcs{
				Get: statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
			},
			wantResult: reconcile.Result{RequeueAfter: Wait},
		},
		{
			name:    "HandleDeletionFails",
			profile: testProfile(finalizer),
			funcs: interceptor.Funcs{
				Get: statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
			},
			handleDeletion: func() (reconcile.Result, error) { return reconcile.Result{}, errTest },
			wantResult:     reconcile.Result{},
			wantErr:        true,
			wantIncError:   true,
			wantHandled:    true,
		},
		{
			// controller-runtime ignores a requeue returned with an error,
			// so it must not be passed on.
			name:    "HandleDeletionFailsWithRequeue_DropsResult",
			profile: testProfile(finalizer),
			funcs: interceptor.Funcs{
				Get: statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
			},
			handleDeletion: func() (reconcile.Result, error) {
				return reconcile.Result{RequeueAfter: Wait}, errTest
			},
			wantResult:   reconcile.Result{},
			wantErr:      true,
			wantIncError: true,
			wantHandled:  true,
		},
		{
			name:    "HandleDeletionRequeues_KeepsStatus",
			profile: testProfile(finalizer),
			funcs: interceptor.Funcs{
				Get:    statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
				Patch:  utiltest.PatchReturns(errors.New("must not be called")),
				Delete: utiltest.DeleteReturns(errors.New("must not be called")),
			},
			handleDeletion: func() (reconcile.Result, error) {
				return reconcile.Result{RequeueAfter: Wait}, nil
			},
			wantResult:  reconcile.Result{RequeueAfter: Wait},
			wantHandled: true,
		},
		{
			// A foreground deletion removes the node statuses first. The
			// finalizer of the node must still be removed.
			name:    "StatusGoneFinalizerPresent_DeletesProfile",
			profile: testProfile(finalizer),
			funcs: interceptor.Funcs{
				Get: func(
					_ context.Context, _ client.WithWatch, key client.ObjectKey, obj client.Object, _ ...client.GetOption,
				) error {
					if _, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
						return kerrors.NewNotFound(schema.GroupResource{}, key.Name)
					}

					return nil
				},
				Patch:  utiltest.PatchReturns(nil),
				Delete: utiltest.DeleteReturns(nil),
			},
			wantResult:  reconcile.Result{},
			wantHandled: true,
		},
		{
			name:    "HappyPath_DeletionSucceeds",
			profile: testProfile(finalizer),
			funcs: interceptor.Funcs{
				Get:    statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
				Patch:  utiltest.PatchReturns(nil),
				Delete: utiltest.DeleteReturns(nil),
			},
			wantResult:  reconcile.Result{},
			wantHandled: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cl := utiltest.NewFakeClient(t, &tc.funcs)
			nsc := testNodeStatus(t, tc.profile, cl)

			incErrorCalled := false
			incError := func(_ string) { incErrorCalled = true }

			handled := false
			handleDeletion := func() (reconcile.Result, error) {
				handled = true

				if tc.handleDeletion != nil {
					return tc.handleDeletion()
				}

				return reconcile.Result{}, nil
			}

			recorder := events.NewFakeRecorder(10)

			gotResult, gotErr := ReconcileDeletion(
				t.Context(), tc.profile, nsc, cl,
				log.Log, recorder, testReasons(), incError, handleDeletion,
			)

			if tc.wantErr {
				require.Error(t, gotErr)
			} else {
				require.NoError(t, gotErr)
			}

			require.Equal(t, tc.wantResult, gotResult)
			require.Equal(t, tc.wantIncError, incErrorCalled)
			require.Equal(t, tc.wantHandled, handled)
		})
	}
}

func TestEnsureNodeStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		profile     *seccompprofileapi.SeccompProfile
		funcs       interceptor.Funcs
		wantCreated bool
		wantErr     bool
	}{
		{
			name:    "AlreadyExists",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			funcs: interceptor.Funcs{
				Get: utiltest.GetReturns(nil),
			},
		},
		{
			name:    "ExistsCheckFails",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			funcs: interceptor.Funcs{
				Get: utiltest.GetReturns(errors.New("api error")),
			},
			wantErr: true,
		},
		{
			name:    "CreatedSuccessfully",
			profile: testProfile(),
			funcs: interceptor.Funcs{
				Get:              utiltest.GetReturns(nil),
				Create:           utiltest.CreateReturns(nil),
				Update:           utiltest.UpdateReturns(nil),
				Patch:            utiltest.PatchReturns(nil),
				Delete:           utiltest.DeleteReturns(nil),
				SubResourcePatch: utiltest.SubResourcePatchReturns(nil),
			},
			wantCreated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nsc := testNodeStatus(t, tc.profile, utiltest.NewFakeClient(t, &tc.funcs))

			gotCreated, _, gotErr := EnsureNodeStatus(t.Context(), nsc, log.Log)

			if tc.wantErr {
				require.Error(t, gotErr)
			} else {
				require.NoError(t, gotErr)
			}

			require.Equal(t, tc.wantCreated, gotCreated)
		})
	}
}

func TestErrorReporter(t *testing.T) {
	t.Parallel()

	reasons := []string{}
	recorder := events.NewFakeRecorder(1)
	reporter := ErrorReporter{
		Record:   recorder,
		IncError: func(reason string) { reasons = append(reasons, reason) },
	}

	reporter.Report(testProfile(), "Reason", util.EventActionUpdate, "message")

	require.Equal(t, []string{"Reason"}, reasons)
	require.Equal(t, "Warning Reason message", <-recorder.Events)

	// A reporter without recorder or metric must not panic.
	ErrorReporter{}.Report(testProfile(), "Reason", util.EventActionUpdate, "message")
}

// fakeEnv is a profile with a fake API server behind it, which serves the
// node status like the API server does.
type fakeEnv struct {
	profile  *seccompprofileapi.SeccompProfile
	client   client.Client
	nsc      *nodestatus.StatusClient
	recorder *events.FakeRecorder
	reasons  []string
}

func newFakeEnv(t *testing.T, funcs *interceptor.Funcs, finalizers ...string) *fakeEnv {
	t.Helper()

	profile := testProfile(finalizers...)
	cl := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(profile.DeepCopy()).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		WithInterceptorFuncs(*funcs).
		Build()

	env := &fakeEnv{
		profile:  profile,
		client:   cl,
		nsc:      testNodeStatus(t, profile, cl),
		recorder: events.NewFakeRecorder(10),
	}

	return env
}

func (e *fakeEnv) reporter() ErrorReporter {
	return ErrorReporter{
		Record:   e.recorder,
		IncError: func(reason string) { e.reasons = append(e.reasons, reason) },
	}
}

func (e *fakeEnv) state(t *testing.T) secprofnodestatusapi.ProfileState {
	t.Helper()

	state, err := e.nsc.State(t.Context())
	require.NoError(t, err)

	return state
}

func TestEnsureNodeStatusOrRequeue(t *testing.T) {
	t.Parallel()

	env := newFakeEnv(t, &interceptor.Funcs{})

	// The status gets created, which is picked up after a delay.
	res, stop, err := EnsureNodeStatusOrRequeue(t.Context(), env.nsc, log.Log)
	require.NoError(t, err)
	require.True(t, stop)
	require.Equal(t, reconcile.Result{RequeueAfter: Wait}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, env.state(t))

	// An existing status lets the reconcile go on.
	res, stop, err = EnsureNodeStatusOrRequeue(t.Context(), env.nsc, log.Log)
	require.NoError(t, err)
	require.False(t, stop)
	require.Equal(t, reconcile.Result{}, res)
}

func TestEnsureNodeStatusOrRequeueError(t *testing.T) {
	t.Parallel()

	errGet := errors.New("get failed")
	env := newFakeEnv(t, &interceptor.Funcs{
		Get: func(
			_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption,
		) error {
			return errGet
		},
	}, util.GetFinalizerNodeString(testNodeName))

	res, stop, err := EnsureNodeStatusOrRequeue(t.Context(), env.nsc, log.Log)
	require.ErrorIs(t, err, errGet)
	require.True(t, stop)
	require.Equal(t, reconcile.Result{}, res)
}

func TestMarkInstalled(t *testing.T) {
	t.Parallel()

	env := newFakeEnv(t, &interceptor.Funcs{})
	_, err := env.nsc.Create(t.Context())
	require.NoError(t, err)

	changed, err := MarkInstalled(t.Context(), env.profile, env.nsc, log.Log, env.reporter())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.state(t))

	changed, err = MarkInstalled(t.Context(), env.profile, env.nsc, log.Log, env.reporter())
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, env.reasons)
	require.Empty(t, env.recorder.Events)
}

func TestMarkInstalledErrors(t *testing.T) {
	t.Parallel()

	errUpdate := errors.New("update failed")

	t.Run("the status cannot be updated", func(t *testing.T) {
		t.Parallel()

		env := newFakeEnv(t, &interceptor.Funcs{
			SubResourcePatch: utiltest.SubResourcePatchReturns(errUpdate),
		})

		// The status cannot be created either without status updates, so
		// it is created directly.
		status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
		status.SetName("seccompprofile-test-profile-" + testNodeName)
		status.SetNamespace("default")
		status.Status.Status = secprofnodestatusapi.ProfileStatePending
		require.NoError(t, env.client.Create(t.Context(), status))

		changed, err := MarkInstalled(t.Context(), env.profile, env.nsc, log.Log, env.reporter())
		require.ErrorIs(t, err, errUpdate)
		require.False(t, changed)
		require.Equal(t, []string{ReasonCannotUpdateStatus}, env.reasons)
		require.Contains(t, <-env.recorder.Events, "Warning "+ReasonCannotUpdateStatus)
	})

	t.Run("the status is missing", func(t *testing.T) {
		t.Parallel()

		env := newFakeEnv(t, &interceptor.Funcs{})

		changed, err := MarkInstalled(t.Context(), env.profile, env.nsc, log.Log, env.reporter())
		require.ErrorContains(t, err, "getting status for installed profile")
		require.False(t, changed)
	})
}

func TestReconcileDisabled(t *testing.T) {
	t.Parallel()

	errRemove := errors.New("remove failed")

	for _, tc := range []struct {
		name            string
		finalizers      []string
		state           secprofnodestatusapi.ProfileState
		removeErr       error
		afterRemoveErr  error
		wantResult      reconcile.Result
		wantErr         error
		wantRemoved     bool
		wantAfterRemove bool
		wantState       secprofnodestatusapi.ProfileState
		wantReason      string
	}{
		{
			name:            "removes an installed profile",
			state:           secprofnodestatusapi.ProfileStateInstalled,
			wantRemoved:     true,
			wantAfterRemove: true,
			wantState:       secprofnodestatusapi.ProfileStateDisabled,
		},
		{
			name:      "skips an already disabled profile",
			state:     secprofnodestatusapi.ProfileStateDisabled,
			wantState: secprofnodestatusapi.ProfileStateDisabled,
		},
		{
			name:       "keeps a profile which pods use",
			finalizers: []string{util.HasActivePodsFinalizerString},
			state:      secprofnodestatusapi.ProfileStateInstalled,
			wantResult: reconcile.Result{RequeueAfter: InUseRetry},
			wantState:  secprofnodestatusapi.ProfileStateInstalled,
		},
		{
			name:        "reports a failed removal",
			state:       secprofnodestatusapi.ProfileStateInstalled,
			removeErr:   errRemove,
			wantErr:     errRemove,
			wantRemoved: true,
			wantState:   secprofnodestatusapi.ProfileStateInstalled,
			wantReason:  "CannotRemove",
		},
		{
			name:            "reports a failure after the removal",
			state:           secprofnodestatusapi.ProfileStateInstalled,
			afterRemoveErr:  errRemove,
			wantErr:         errRemove,
			wantRemoved:     true,
			wantAfterRemove: true,
			wantState:       secprofnodestatusapi.ProfileStateInstalled,
			wantReason:      "CannotUpdateStatus",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newFakeEnv(t, &interceptor.Funcs{}, tc.finalizers...)
			_, err := env.nsc.Create(t.Context())
			require.NoError(t, err)
			require.NoError(t, env.nsc.SetNodeStatus(t.Context(), tc.state))

			removed, afterRemove := false, false

			res, err := ReconcileDisabled(
				t.Context(), env.profile, env.nsc, log.Log, env.reporter(), testReasons(),
				func() error {
					removed = true

					return tc.removeErr
				},
				func() error {
					afterRemove = true

					return tc.afterRemoveErr
				},
			)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Equal(t, []string{tc.wantReason}, env.reasons)
			} else {
				require.NoError(t, err)
				require.Empty(t, env.reasons)
			}

			require.Equal(t, tc.wantResult, res)
			require.Equal(t, tc.wantRemoved, removed)
			require.Equal(t, tc.wantAfterRemove, afterRemove)
			require.Equal(t, tc.wantState, env.state(t))
		})
	}

	t.Run("works without an after removal step", func(t *testing.T) {
		t.Parallel()

		env := newFakeEnv(t, &interceptor.Funcs{})
		_, err := env.nsc.Create(t.Context())
		require.NoError(t, err)

		res, err := ReconcileDisabled(
			t.Context(), env.profile, env.nsc, log.Log, env.reporter(), testReasons(),
			func() error { return nil }, nil,
		)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res)
		require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, env.state(t))
	})
}
