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
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
)

func inheritingProfile(name string, inherits ...string) *selinuxprofileapi.SelinuxProfile {
	sp := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testReconcileNamespace},
	}

	for _, inherit := range inherits {
		sp.Spec.Inherit = append(sp.Spec.Inherit, selinuxprofileapi.PolicyRef{
			Kind: selinuxprofileapi.SelinuxProfilePolicyKind,
			Name: inherit,
		})
	}

	return sp
}

func TestCheckInheritCycle(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		profiles  []client.Object
		inherits  string
		wantCycle bool
		wantErr   error
	}{
		"self reference": {
			profiles:  []client.Object{inheritingProfile("a", "a")},
			inherits:  "a",
			wantCycle: true,
		},
		"cycle through another profile": {
			profiles: []client.Object{
				inheritingProfile("a", "b"),
				inheritingProfile("b", "c"),
				inheritingProfile("c", "a"),
			},
			inherits:  "b",
			wantCycle: true,
		},
		"many inherited profiles on one level": {
			profiles: func() []client.Object {
				wide := inheritingProfile("b")
				objs := make([]client.Object, 0, maxInheritDepth+7)
				objs = append(objs, inheritingProfile("a", "b"), wide)

				for i := range maxInheritDepth + 5 {
					name := fmt.Sprintf("leaf-%d", i)
					wide.Spec.Inherit = append(wide.Spec.Inherit, selinuxprofileapi.PolicyRef{
						Kind: selinuxprofileapi.SelinuxProfilePolicyKind,
						Name: name,
					})
					objs = append(objs, inheritingProfile(name))
				}

				return objs
			}(),
			inherits: "b",
		},
		"chain too deep": {
			profiles: func() []client.Object {
				objs := make([]client.Object, 0, maxInheritDepth+2)
				objs = append(objs, inheritingProfile("a", "level-0"))

				for i := range maxInheritDepth + 1 {
					objs = append(objs, inheritingProfile(
						fmt.Sprintf("level-%d", i), fmt.Sprintf("level-%d", i+1),
					))
				}

				return objs
			}(),
			inherits: "level-0",
			wantErr:  ErrInheritTooDeep,
		},
		"chain without cycle": {
			profiles: []client.Object{
				inheritingProfile("a", "b"),
				inheritingProfile("b", "c", "missing"),
				inheritingProfile("c"),
			},
			inherits: "b",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cli := fake.NewClientBuilder().
				WithScheme(testScheme(t)).
				WithObjects(tc.profiles...).
				Build()

			sph := &selinuxProfileHandler{sp: &selinuxprofileapi.SelinuxProfile{}, cli: cli}
			require.NoError(t, cli.Get(t.Context(),
				types.NamespacedName{Name: "a", Namespace: testReconcileNamespace}, sph.sp))

			err := sph.handleInheritSPOPolicy(t.Context(), selinuxprofileapi.PolicyRef{
				Kind: selinuxprofileapi.SelinuxProfilePolicyKind,
				Name: tc.inherits,
			}, testReconcileNamespace)

			switch {
			case tc.wantCycle:
				require.ErrorIs(t, err, ErrInheritCycle)
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestInheritedProfilesInstalledReportsUnusableAncestors(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		mutate       func(*selinuxprofileapi.SelinuxProfile)
		state        secprofnodestatusapi.ProfileState
		wantUnusable bool
		wantReady    bool
	}{
		"installed":   {state: secprofnodestatusapi.ProfileStateInstalled, wantReady: true},
		"in progress": {state: secprofnodestatusapi.ProfileStateInProgress},
		"no status":   {},
		"error":       {state: secprofnodestatusapi.ProfileStateError, wantUnusable: true},
		"disabled": {
			mutate: func(sp *selinuxprofileapi.SelinuxProfile) {
				sp.Spec.State = profilebasev1.SpecStateDisabled
			},
			wantUnusable: true,
		},
		"partial": {
			mutate: func(sp *selinuxprofileapi.SelinuxProfile) {
				sp.Labels = map[string]string{profilebasev1.ProfilePartialLabel: "true"}
			},
			wantUnusable: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ancestor := testProfile()
			ancestor.Name = "ancestor"

			if tc.mutate != nil {
				tc.mutate(ancestor)
			}

			cli := fake.NewClientBuilder().
				WithScheme(testScheme(t)).
				WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
				WithObjects(ancestor).
				Build()

			if tc.state != "" {
				ns, err := nodestatus.NewForProfileOnNode(ancestor, cli, testReconcileNode)
				require.NoError(t, err)
				_, err = ns.Create(t.Context())
				require.NoError(t, err)
				require.NoError(t, ns.SetNodeStatus(t.Context(), tc.state))
			}

			r := &ReconcileSelinux{client: cli, nodeName: testReconcileNode}

			ready, err := r.inheritedProfilesInstalled(t.Context(), &inheritingFakeHandler{
				ancestors: []selinuxprofileapi.SelinuxProfileObject{ancestor},
			}, logr.Discard())

			if tc.wantUnusable {
				require.ErrorIs(t, err, errInheritedProfileUnusable)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.wantReady, ready)
		})
	}
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileUnusableAncestorSetsError(t *testing.T) {
	ancestor := testProfile()
	ancestor.Name = "ancestor"
	ancestor.Spec.State = profilebasev1.SpecStateDisabled

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))
	require.NoError(t, f.client.Create(context.Background(), ancestor))

	f.r.objectHandlerInit = func(
		ctx context.Context, c client.Client, key types.NamespacedName,
	) (SelinuxObjectHandler, error) {
		oh := &inheritingFakeHandler{
			fakeHandler: fakeHandler{sp: &selinuxprofileapi.SelinuxProfile{}},
			ancestors:   []selinuxprofileapi.SelinuxProfileObject{ancestor},
		}
		err := oh.Init(ctx, c, key)

		return oh, err
	}

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: inheritRetryInterval}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonCannotInstallPolicy+" "))
}

// The check for a conflicting system module must not be skipped because the
// first pass returned before reaching it, and a module installed by this
// operator must not count as conflicting after the SPOd pod got replaced.
//
//nolint:paralleltest // uses t.Setenv
func TestReconcileSystemModuleConflictCheck(t *testing.T) {
	var ready atomic.Bool

	f := newReconcileFixture(t, testProfile(), nil, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ready") {
			if ready.Load() {
				writeBody(t, w, `{"ready": true}`)
			} else {
				writeBody(t, w, `{"ready": false}`)
			}

			return
		}

		writeBody(t, w, `{"status": "Installed", "msg": ""}`)
	})

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)

	moduleDir := filepath.Join(
		f.r.moduleStorePath, "targeted", "active", "modules", "100", testReconcileProfile,
	)
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	ready.Store(true)

	_, err = f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)

	policyFile := filepath.Join(f.r.policyDir, testReconcileProfile+".cil")
	_, err = os.Stat(policyFile)
	require.True(t, os.IsNotExist(err), "the system module must not be replaced")

	// Once the system module is gone, the policy gets installed.
	require.NoError(t, os.RemoveAll(moduleDir))

	for range 2 {
		_, err = f.r.Reconcile(context.Background(), f.request)
		require.NoError(t, err)
	}

	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)

	// selinuxd installs the module. A new SPOd pod starts with an empty
	// policy directory, but the module is still ours.
	require.NoError(t, os.MkdirAll(moduleDir, 0o755))
	require.NoError(t, os.Remove(policyFile))

	_, err = f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.FileExists(t, policyFile)
	require.NotEqual(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)
}
