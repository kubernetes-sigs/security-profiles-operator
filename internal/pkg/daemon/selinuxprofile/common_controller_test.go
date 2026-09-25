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

package selinuxprofile

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func TestIsSystemSELinuxModule(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, modules ...string) string {
		t.Helper()

		store := t.TempDir()
		modulesDir := filepath.Join(store, "targeted", "active", "modules", "100")
		require.NoError(t, os.MkdirAll(modulesDir, 0o755))

		for _, m := range modules {
			require.NoError(t, os.Mkdir(filepath.Join(modulesDir, m), 0o755))
		}

		return store
	}

	cases := []struct {
		name    string
		modules []string
		query   string
		want    bool
	}{
		{
			name:    "system module kerberos is detected",
			modules: []string{"kerberos", "container"},
			query:   "kerberos",
			want:    true,
		},
		{
			name:    "system module container is detected",
			modules: []string{"kerberos", "container"},
			query:   "container",
			want:    true,
		},
		{
			name:    "custom name does not conflict",
			modules: []string{"kerberos", "container"},
			query:   "my-custom-profile",
			want:    false,
		},
		{
			name:    "prefixed name does not conflict",
			modules: []string{"kerberos"},
			query:   "custom-kerberos",
			want:    false,
		},
		{
			name:    "empty module store",
			modules: nil,
			query:   "kerberos",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := setup(t, tc.modules...)
			got := isSELinuxModuleInstalled(store, tc.query)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestIsSystemSELinuxModuleNonexistentPath(t *testing.T) {
	t.Parallel()

	got := isSELinuxModuleInstalled("/nonexistent/path", "kerberos")
	require.False(t, got)
}

func TestReconcileDeletionWithActivePods(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, selinuxprofileapi.AddToScheme(scheme))
	require.NoError(t, secprofnodestatusapi.AddToScheme(scheme))

	profile := &selinuxprofileapi.SelinuxProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: selinuxprofileapi.GroupVersion.String(),
			Kind:       "SelinuxProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "profile",
			Namespace:  "default",
			Finalizers: []string{util.HasActivePodsFinalizerString},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(profile).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		Build()

	nsc, err := nodestatus.NewForProfileOnNode(profile, cli, "test-node")
	require.NoError(t, err)
	_, err = nsc.Create(t.Context())
	require.NoError(t, err)
	require.NoError(t, cli.Delete(t.Context(), profile))

	// The httpc is nil on purpose: reaching selinuxd would mean the policy
	// is about to be removed although pods still use it.
	r := &ReconcileSelinux{
		client:            cli,
		record:            events.NewFakeRecorder(10),
		log:               logr.Discard(),
		objectHandlerInit: newSelinuxProfileHandler,
		nodeName:          "test-node",
	}

	res, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "profile", Namespace: "default"},
	})
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
}

// A Failed status from selinuxd during deletion must keep the finalizer while
// the module is still installed, and must not block the deletion when the
// module is gone.
func TestReconcileDeletionWithFailedRemoval(t *testing.T) {
	t.Parallel()

	const policyName = "spo-test-failed-removal"

	for name, tc := range map[string]struct {
		moduleInstalled bool
		wantErr         error
		wantFinalizer   bool
	}{
		"module still installed": {
			moduleInstalled: true,
			wantErr:         errPolicyRemovalFailed,
			wantFinalizer:   true,
		},
		"module not installed": {
			moduleInstalled: false,
			wantFinalizer:   false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := t.TempDir()
			modulesDir := filepath.Join(store, "targeted", "active", "modules", "400")
			require.NoError(t, os.MkdirAll(modulesDir, 0o755))

			if tc.moduleInstalled {
				require.NoError(t, os.Mkdir(filepath.Join(modulesDir, policyName), 0o755))
			}

			scheme := runtime.NewScheme()
			require.NoError(t, selinuxprofileapi.AddToScheme(scheme))
			require.NoError(t, secprofnodestatusapi.AddToScheme(scheme))

			profile := &selinuxprofileapi.SelinuxProfile{
				TypeMeta: metav1.TypeMeta{
					APIVersion: selinuxprofileapi.GroupVersion.String(),
					Kind:       "SelinuxProfile",
				},
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: "default"},
			}

			cli := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(profile).
				WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
				Build()

			nsc, err := nodestatus.NewForProfileOnNode(profile, cli, "test-node")
			require.NoError(t, err)
			_, err = nsc.Create(t.Context())
			require.NoError(t, err)
			require.NoError(t, cli.Delete(t.Context(), profile))

			r := &ReconcileSelinux{
				client:            cli,
				record:            events.NewFakeRecorder(10),
				metrics:           metrics.New(),
				log:               logr.Discard(),
				objectHandlerInit: newSelinuxProfileHandler,
				moduleStorePath:   store,
				nodeName:          "test-node",
				httpc: selinuxdTestClient(t, func(w http.ResponseWriter, req *http.Request) {
					if req.URL.Path == "/ready" {
						writeBody(t, w, `{"ready": true}`)

						return
					}

					writeBody(t, w, `{"status": "Failed", "msg": "semodule failed"}`)
				}),
			}

			key := types.NamespacedName{Name: policyName, Namespace: "default"}

			// The first pass marks the node status as terminating.
			res, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: key})
			require.NoError(t, err)
			require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)

			_, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: key})

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			got := &selinuxprofileapi.SelinuxProfile{}
			getErr := cli.Get(t.Context(), key, got)

			if tc.wantFinalizer {
				require.NoError(t, getErr)
				require.Contains(t, got.GetFinalizers(), util.GetFinalizerNodeString("test-node"))
			} else {
				require.True(t, kerrors.IsNotFound(getErr), "profile should be gone: %v", getErr)
			}
		})
	}
}
