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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const testNodeName = "test-node"

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	seccompprofileapi.SchemeBuilder.AddToScheme(s)    //nolint:errcheck // test helper
	secprofnodestatusapi.SchemeBuilder.AddToScheme(s) //nolint:errcheck // test helper

	return s
}

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

// statusGetFn returns a get function that reports a node status in the
// provided state and leaves all other objects untouched.
func statusGetFn(state secprofnodestatusapi.ProfileState) func(
	context.Context, client.ObjectKey, client.Object, ...client.GetOption,
) error {
	return func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
		if ns, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
			ns.Status.Status = state
			ns.Labels = map[string]string{
				secprofnodestatusapi.StatusStateLabel: string(state),
			}
		}

		return nil
	}
}

func TestReconcileDeletion(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")
	finalizer := util.GetFinalizerNodeString(testNodeName)

	cases := []struct {
		name           string
		profile        *seccompprofileapi.SeccompProfile
		mockClient     *utiltest.MockClient
		handleDeletion func() (reconcile.Result, error)
		wantResult     reconcile.Result
		wantErr        bool
		wantIncError   bool
		wantHandled    bool
	}{
		{
			name:    "NoFinalizer_NothingToDo",
			profile: testProfile(),
			mockClient: &utiltest.MockClient{
				MockGet:    utiltest.NewMockGetFn(errors.New("must not be called")),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
			wantResult: reconcile.Result{},
		},
		{
			name:    "StatusExistsNotTerminating_SetsTerminatingAndRequeues",
			profile: testProfile(finalizer),
			mockClient: &utiltest.MockClient{
				MockGet:                     statusGetFn(secprofnodestatusapi.ProfileStatePending),
				MockUpdate:                  utiltest.NewMockUpdateFn(nil),
				MockSubResourceWriterUpdate: utiltest.NewMockSubResourceWriterUpdateFn(nil),
				MockScheme:                  utiltest.NewMockSchemeFn(testScheme()),
			},
			wantResult: reconcile.Result{RequeueAfter: Wait},
		},
		{
			name:    "StatusExistsTerminating_ActivePodsFinalizer_Requeues",
			profile: testProfile(finalizer, util.HasActivePodsFinalizerString),
			mockClient: &utiltest.MockClient{
				MockGet:    statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
			wantResult: reconcile.Result{RequeueAfter: Wait},
		},
		{
			name:    "HandleDeletionFails",
			profile: testProfile(finalizer),
			mockClient: &utiltest.MockClient{
				MockGet:    statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
			handleDeletion: func() (reconcile.Result, error) { return reconcile.Result{}, errTest },
			wantResult:     reconcile.Result{},
			wantErr:        true,
			wantIncError:   true,
			wantHandled:    true,
		},
		{
			name:    "HandleDeletionRequeues_KeepsStatus",
			profile: testProfile(finalizer),
			mockClient: &utiltest.MockClient{
				MockGet:    statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
				MockUpdate: utiltest.NewMockUpdateFn(errors.New("must not be called")),
				MockDelete: utiltest.NewMockDeleteFn(errors.New("must not be called")),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
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
			mockClient: &utiltest.MockClient{
				MockGet: func(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if _, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
						return kerrors.NewNotFound(schema.GroupResource{}, key.Name)
					}

					return nil
				},
				MockUpdate: utiltest.NewMockUpdateFn(nil),
				MockDelete: utiltest.NewMockDeleteFn(nil),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
			wantResult:  reconcile.Result{},
			wantHandled: true,
		},
		{
			name:    "HappyPath_DeletionSucceeds",
			profile: testProfile(finalizer),
			mockClient: &utiltest.MockClient{
				MockGet:    statusGetFn(secprofnodestatusapi.ProfileStateTerminating),
				MockUpdate: utiltest.NewMockUpdateFn(nil),
				MockDelete: utiltest.NewMockDeleteFn(nil),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
			wantResult:  reconcile.Result{},
			wantHandled: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nsc := testNodeStatus(t, tc.profile, tc.mockClient)

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
				t.Context(), tc.profile, nsc, tc.mockClient,
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
		mockClient  *utiltest.MockClient
		wantCreated bool
		wantErr     bool
	}{
		{
			name:    "AlreadyExists",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &utiltest.MockClient{
				MockGet:    utiltest.NewMockGetFn(nil),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
		},
		{
			name:    "ExistsCheckFails",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &utiltest.MockClient{
				MockGet:    utiltest.NewMockGetFn(errors.New("api error")),
				MockScheme: utiltest.NewMockSchemeFn(testScheme()),
			},
			wantErr: true,
		},
		{
			name:    "CreatedSuccessfully",
			profile: testProfile(),
			mockClient: &utiltest.MockClient{
				MockGet:                     utiltest.NewMockGetFn(nil),
				MockCreate:                  utiltest.NewMockCreateFn(nil),
				MockUpdate:                  utiltest.NewMockUpdateFn(nil),
				MockDelete:                  utiltest.NewMockDeleteFn(nil),
				MockSubResourceWriterUpdate: utiltest.NewMockSubResourceWriterUpdateFn(nil),
				MockScheme:                  utiltest.NewMockSchemeFn(testScheme()),
			},
			wantCreated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			nsc := testNodeStatus(t, tc.profile, tc.mockClient)

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
