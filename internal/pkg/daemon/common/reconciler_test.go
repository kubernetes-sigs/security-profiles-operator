/*
Copyright 2026 The Kubernetes Authors.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const testNodeName = "test-node"

func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	seccompprofileapi.SchemeBuilder.AddToScheme(s) //nolint:errcheck // test helper
	statusv1alpha1.SchemeBuilder.AddToScheme(s)    //nolint:errcheck // test helper

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

	nsc, err := nodestatus.NewForProfile(profile, cl)
	require.NoError(t, err)

	return nsc
}

//nolint:paralleltest // subtests modify environment variables and cannot run in parallel
func TestReconcileDeletion(t *testing.T) {
	t.Setenv("NODE_NAME", testNodeName)

	errTest := errors.New("test error")

	cases := []struct {
		name           string
		profile        *seccompprofileapi.SeccompProfile
		mockClient     *util.MockClient
		handleDeletion func() error
		wantResult     reconcile.Result
		wantErr        bool
		wantIncError   bool
	}{
		{
			name:    "NoStatusExists_NoDeletionNeeded",
			profile: testProfile(),
			mockClient: &util.MockClient{
				MockGet:    util.NewMockGetFn(errors.New("not found")),
				MockUpdate: util.NewMockUpdateFn(nil),
				MockDelete: util.NewMockDeleteFn(nil),
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			handleDeletion: func() error { return nil },
			wantResult:     reconcile.Result{},
			wantErr:        true,
		},
		{
			name:    "StatusExistsNotTerminating_SetsTerminatingAndRequeues",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &util.MockClient{
				MockGet: func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if ns, ok := obj.(*statusv1alpha1.SecurityProfileNodeStatus); ok {
						ns.Status = statusv1alpha1.ProfileStatePending
						ns.Labels = map[string]string{
							statusv1alpha1.StatusStateLabel: string(statusv1alpha1.ProfileStatePending),
						}
					}

					return nil
				},
				MockUpdate: util.NewMockUpdateFn(nil),
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			handleDeletion: func() error { return nil },
			wantResult:     reconcile.Result{Requeue: true, RequeueAfter: Wait},
			wantErr:        false,
		},
		{
			name:    "StatusExistsTerminating_ActivePodsFinalizer_Requeues",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName), util.HasActivePodsFinalizerString),
			mockClient: &util.MockClient{
				MockGet: func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if ns, ok := obj.(*statusv1alpha1.SecurityProfileNodeStatus); ok {
						ns.Status = statusv1alpha1.ProfileStateTerminating
						ns.Labels = map[string]string{
							statusv1alpha1.StatusStateLabel: string(statusv1alpha1.ProfileStateTerminating),
						}
					}

					return nil
				},
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			handleDeletion: func() error { return nil },
			wantResult:     reconcile.Result{RequeueAfter: Wait},
			wantErr:        false,
		},
		{
			name:    "HandleDeletionFails",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &util.MockClient{
				MockGet: func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if ns, ok := obj.(*statusv1alpha1.SecurityProfileNodeStatus); ok {
						ns.Status = statusv1alpha1.ProfileStateTerminating
						ns.Labels = map[string]string{
							statusv1alpha1.StatusStateLabel: string(statusv1alpha1.ProfileStateTerminating),
						}
					}

					return nil
				},
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			handleDeletion: func() error { return errTest },
			wantResult:     reconcile.Result{},
			wantErr:        true,
			wantIncError:   true,
		},
		{
			name:    "HappyPath_DeletionSucceeds",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &util.MockClient{
				MockGet: func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if ns, ok := obj.(*statusv1alpha1.SecurityProfileNodeStatus); ok {
						ns.Status = statusv1alpha1.ProfileStateTerminating
						ns.Labels = map[string]string{
							statusv1alpha1.StatusStateLabel: string(statusv1alpha1.ProfileStateTerminating),
						}
					}

					return nil
				},
				MockUpdate: util.NewMockUpdateFn(nil),
				MockDelete: util.NewMockDeleteFn(nil),
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			handleDeletion: func() error { return nil },
			wantResult:     reconcile.Result{},
			wantErr:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsc := testNodeStatus(t, tc.profile, tc.mockClient)

			incErrorCalled := false
			incError := func(_ string) { incErrorCalled = true }

			recorder := record.NewFakeRecorder(10)

			gotResult, gotErr := ReconcileDeletion(
				t.Context(), tc.profile, nsc, tc.mockClient,
				log.Log, recorder, testReasons(), incError, tc.handleDeletion,
			)

			if tc.wantErr {
				require.Error(t, gotErr)
			} else {
				require.NoError(t, gotErr)
			}

			require.Equal(t, tc.wantResult, gotResult)

			if tc.wantIncError {
				require.True(t, incErrorCalled, "expected incError to be called")
			}
		})
	}
}

//nolint:paralleltest // subtests modify environment variables and cannot run in parallel
func TestEnsureNodeStatus(t *testing.T) {
	t.Setenv("NODE_NAME", testNodeName)

	cases := []struct {
		name        string
		profile     *seccompprofileapi.SeccompProfile
		mockClient  *util.MockClient
		wantCreated bool
		wantResult  reconcile.Result
		wantErr     bool
	}{
		{
			name:    "AlreadyExists",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &util.MockClient{
				MockGet:    util.NewMockGetFn(nil),
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			wantCreated: false,
			wantResult:  reconcile.Result{},
			wantErr:     false,
		},
		{
			name:    "ExistsCheckFails",
			profile: testProfile(util.GetFinalizerNodeString(testNodeName)),
			mockClient: &util.MockClient{
				MockGet:    util.NewMockGetFn(errors.New("api error")),
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			wantCreated: false,
			wantResult:  reconcile.Result{},
			wantErr:     true,
		},
		{
			name:    "CreatedSuccessfully",
			profile: testProfile(),
			mockClient: &util.MockClient{
				MockGet:    util.NewMockGetFn(nil),
				MockCreate: util.NewMockCreateFn(nil),
				MockUpdate: util.NewMockUpdateFn(nil),
				MockScheme: util.NewMockSchemeFn(testScheme()),
			},
			wantCreated: true,
			wantResult:  reconcile.Result{RequeueAfter: Wait},
			wantErr:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nsc := testNodeStatus(t, tc.profile, tc.mockClient)

			gotCreated, gotResult, gotErr := EnsureNodeStatus(t.Context(), nsc, log.Log)

			if tc.wantErr {
				require.Error(t, gotErr)
			} else {
				require.NoError(t, gotErr)
			}

			require.Equal(t, tc.wantCreated, gotCreated)
			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}
