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

package apparmorprofile

import (
	"context"
	"errors"
	"testing"

	_ "github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func TestReconcile(t *testing.T) {
	t.Parallel()

	name := "cool-profile"
	namespace := "cool-namespace"

	cases := []struct {
		name       string
		rec        *Reconciler
		req        reconcile.Request
		wantResult reconcile.Result
		wantErr    error
	}{
		{
			name: "ProfileNotFound",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet: util.NewMockGetFn(kerrors.NewNotFound(schema.GroupResource{}, name)),
				},
				log:     log.Log,
				metrics: metrics.New(),
				manager: NewAppArmorProfileManager(log.Log),
			},
			req: reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
			},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "GotProfile",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet:                     util.NewMockGetFn(nil),
					MockUpdate:                  util.NewMockUpdateFn(nil),
					MockSubResourceWriterUpdate: util.NewMockSubResourceWriterUpdateFn(nil),
				},
				log:     log.Log,
				record:  record.NewFakeRecorder(10),
				manager: NewAppArmorProfileManager(log.Log),
				metrics: metrics.New(),
			},
			req: reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
			},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "NotEnabled",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet:                     util.NewMockGetFn(nil),
					MockUpdate:                  util.NewMockUpdateFn(nil),
					MockSubResourceWriterUpdate: util.NewMockSubResourceWriterUpdateFn(nil),
				},
				log:     log.Log,
				record:  record.NewFakeRecorder(10),
				manager: &FakeProfileManager{enabled: false},
				metrics: metrics.New(),
			},
			req: reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
			},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.rec.Reconcile(t.Context(), tc.req)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			}

			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

type FakeProfileManager struct {
	enabled   bool
	installed bool
	err       error

	// gotPreviouslyInstalled records what the reconciler passed, so a test can
	// assert that the node status is what vouches for an unmarked profile.
	gotPreviouslyInstalled bool

	// gotRemoveOwnedByUs records what the reconciler passed on removal.
	gotRemoveOwnedByUs bool
}

func (f *FakeProfileManager) Enabled() bool {
	return f.enabled
}

func (f *FakeProfileManager) InstallProfile(
	_ profilebaseapi.StatusBaseUser, previouslyInstalled bool,
) (bool, error) {
	f.gotPreviouslyInstalled = previouslyInstalled

	return f.installed, f.err
}

func (f *FakeProfileManager) RemoveProfile(_ profilebaseapi.StatusBaseUser, ownedByUs bool) error {
	f.gotRemoveOwnedByUs = ownedByUs

	return f.err
}

// TestHandleDeletionOwnership covers the evidence passed on removal. Only this
// node's status recording a successful install may vouch for a profile whose
// policy file is gone, otherwise deleting an AppArmorProfile named after a
// container runtime's default profile would unload it from the host.
func TestHandleDeletionOwnership(t *testing.T) {
	for _, tc := range []struct {
		name        string
		getErr      error
		annotations map[string]string
		want        bool
		wantErr     bool
	}{
		{
			name:        "installed on this node",
			annotations: map[string]string{installedAnnotation: "true"},
			want:        true,
		},
		{
			name: "never installed on this node",
			want: false,
		},
		{
			name:   "no node status",
			getErr: kerrors.NewNotFound(schema.GroupResource{}, "status"),
			want:   false,
		},
		{
			name:    "node status cannot be read",
			getErr:  errors.New("boom"),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.NodeNameEnvKey, "worker-1")

			profile := &apparmorprofileapi.AppArmorProfile{
				TypeMeta:   metav1.TypeMeta{Kind: "AppArmorProfile"},
				ObjectMeta: metav1.ObjectMeta{Name: "docker-default"},
			}
			manager := &FakeProfileManager{}
			rec := &Reconciler{
				client: &util.MockClient{
					MockGet: func(_ context.Context, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
						obj.SetAnnotations(tc.annotations)

						return tc.getErr
					},
				},
				log:     log.Log,
				metrics: metrics.New(),
				manager: manager,
			}

			nodeStatus, err := nodestatus.NewForProfile(profile, rec.client)
			require.NoError(t, err)

			err = rec.handleDeletion(t.Context(), profile, nodeStatus)
			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, manager.gotRemoveOwnedByUs)
		})
	}
}
