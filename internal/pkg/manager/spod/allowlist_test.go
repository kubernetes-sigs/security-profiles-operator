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

package spod

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func allowListProfile(name, base string, syscalls ...string) *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: seccompprofileapi.SeccompProfileSpec{
			BaseProfileName: base,
			DefaultAction:   seccompprofileapi.ActErrno,
			Syscalls: []seccompprofileapi.Syscall{{
				Action: seccompprofileapi.ActAllow,
				Names:  syscalls,
			}},
		},
	}
}

func allowListProfiles() []client.Object {
	deleting := allowListProfile("deleting", "", "write")
	deleting.Finalizers = []string{"keep"}
	deleting.DeletionTimestamp = &metav1.Time{}

	return []client.Object{
		allowListProfile("allowed", "", "read"),
		allowListProfile("forbidden", "", "read", "write"),
		// Inherits a forbidden syscall from its local base profile.
		allowListProfile("base", "", "write"),
		allowListProfile("child", "base", "read"),
		// The daemons pull OCI base profiles, so the manager leaves the
		// profile to them.
		allowListProfile("oci-child", "oci://registry/base:v1", "read"),
		// A base profile which does not exist cannot be resolved either.
		allowListProfile("missing-base-child", "missing", "write"),
		deleting,
	}
}

func reconcileAllowList(t *testing.T, r *ReconcileSPOd) error {
	t.Helper()

	_, err := r.reconcileAllowList(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: config.SPOdName, Namespace: testNamespace},
	})

	return err
}

func remainingProfiles(t *testing.T, cl client.Client) []string {
	t.Helper()

	list := &seccompprofileapi.SeccompProfileList{}
	require.NoError(t, cl.List(t.Context(), list))

	names := make([]string, 0, len(list.Items))
	for i := range list.Items {
		names = append(names, list.Items[i].Name)
	}

	return names
}

func TestReconcileAllowList(t *testing.T) {
	t.Parallel()

	all := []string{
		"allowed", "forbidden", "base", "child", "oci-child", "missing-base-child", "deleting",
	}

	for _, tc := range []struct {
		name          string
		security      spodapi.SPODSecurityConfig
		wantRemaining []string
		wantEvent     string
	}{
		{
			name:          "deletes the profiles using forbidden syscalls",
			security:      spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}},
			wantRemaining: []string{"allowed", "oci-child", "missing-base-child", "deleting"},
		},
		{
			name: "only checks the allowed actions",
			security: spodapi.SPODSecurityConfig{
				AllowedSyscalls:       []string{"read"},
				AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActLog},
			},
			wantRemaining: all,
		},
		{
			name:          "keeps every profile for an empty allow list",
			wantRemaining: all,
		},
		{
			name: "never deletes profiles because of an invalid action",
			security: spodapi.SPODSecurityConfig{
				AllowedSyscalls:       []string{"read"},
				AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActErrno},
			},
			wantRemaining: all,
			wantEvent:     "Warning " + reasonInvalidSPODConfig,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spod := testSPOD()
			spod.Spec.Security = tc.security

			r, cl, recorder := newReconcileTest(
				t,
				spod,
				&interceptor.Funcs{},
				allowListProfiles()...)

			require.NoError(t, reconcileAllowList(t, r))
			require.ElementsMatch(t, tc.wantRemaining, remainingProfiles(t, cl))

			if tc.wantEvent == "" {
				require.Empty(t, recorder.Events)
			} else {
				require.Len(t, recorder.Events, 1)
				require.Contains(t, <-recorder.Events, tc.wantEvent)
			}
		})
	}
}

func TestReconcileAllowListMissingSPOD(t *testing.T) {
	t.Parallel()

	r, _, _ := newReconcileTest(t, testSPOD(), &interceptor.Funcs{})

	_, err := r.reconcileAllowList(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: testNamespace},
	})
	require.NoError(t, err)
}

// The daemons ignore the allow lists of a SPOD which is not named spod, so
// they do not delete any profile either.
func TestReconcileAllowListUnsupportedName(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Name = "other"
	spod.Spec.Security = spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}}

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{}, allowListProfiles()...)

	_, err := r.reconcileAllowList(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(spod),
	})
	require.NoError(t, err)
	require.Len(t, remainingProfiles(t, cl), len(allowListProfiles()))
}

func TestReconcileAllowListDeleteErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		err     error
		wantErr bool
	}{
		{
			name: "profile deleted already",
			err:  apierrors.NewNotFound(schema.GroupResource{}, "forbidden"),
		},
		{
			name:    "failing deletion gets retried",
			err:     errTest,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spod := testSPOD()
			spod.Spec.Security.AllowedSyscalls = []string{"read"}

			deletes := 0
			funcs := &interceptor.Funcs{
				Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
					deletes++

					return tc.err
				},
			}

			r, _, _ := newReconcileTest(
				t, spod, funcs, allowListProfile("forbidden", "", "read", "write"),
			)

			err := reconcileAllowList(t, r)
			require.Equal(t, 1, deletes)

			if tc.wantErr {
				require.ErrorIs(t, err, errTest)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func enforcedAllowList(t *testing.T, cl client.Client) (string, bool) {
	t.Helper()

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, spod))

	hash, ok := spod.GetAnnotations()[enforcedAllowListAnnotation]

	return hash, ok
}

// The SPOD passes the predicate again whenever the manager starts, which must
// not delete the profiles that got created after the allow lists were
// enforced, because the daemons only reject those.
func TestReconcileAllowListEnforcesOnce(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Spec.Security.AllowedSyscalls = []string{"read"}

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{},
		allowListProfile("forbidden", "", "read", "write"))

	require.NoError(t, reconcileAllowList(t, r))
	require.Empty(t, remainingProfiles(t, cl))

	hash, ok := enforcedAllowList(t, cl)
	require.True(t, ok)
	require.Equal(t, allowListHash(&spod.Spec.Security), hash)

	require.NoError(t, cl.Create(t.Context(), allowListProfile("created-later", "", "write")))
	require.NoError(t, reconcileAllowList(t, r))
	require.Equal(t, []string{"created-later"}, remainingProfiles(t, cl))

	// Removing the allow lists removes the hash, so that setting the same
	// allow lists again enforces them again.
	current := &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(spod), current))
	current.Spec.Security.AllowedSyscalls = nil
	require.NoError(t, cl.Update(t.Context(), current))
	require.NoError(t, reconcileAllowList(t, r))

	_, ok = enforcedAllowList(t, cl)
	require.False(t, ok)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(spod), current))
	current.Spec.Security.AllowedSyscalls = []string{"read"}
	require.NoError(t, cl.Update(t.Context(), current))
	require.NoError(t, reconcileAllowList(t, r))
	require.Empty(t, remainingProfiles(t, cl))
}

func TestReconcileAllowListNotEnforced(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		security spodapi.SPODSecurityConfig
		funcs    *interceptor.Funcs
	}{
		{
			name: "invalid action",
			security: spodapi.SPODSecurityConfig{
				AllowedSyscalls:       []string{"read"},
				AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActErrno},
			},
			funcs: &interceptor.Funcs{},
		},
		{
			name:     "failing deletion",
			security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}},
			funcs: &interceptor.Funcs{
				Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
					return errTest
				},
			},
		},
	} {
		for _, previous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/previous=%v", tc.name, previous), func(t *testing.T) {
				t.Parallel()

				spod := testSPOD()
				spod.Spec.Security = tc.security

				// The hash of other allow lists which were enforced before
				// must not stay.
				if previous {
					spod.Annotations = map[string]string{
						enforcedAllowListAnnotation: allowListHash(&spodapi.SPODSecurityConfig{
							AllowedSyscalls: []string{"write"},
						}),
					}
				}

				r, cl, _ := newReconcileTest(t, spod, tc.funcs,
					allowListProfile("forbidden", "", "read", "write"))

				//nolint:errcheck // only the missing hash matters
				reconcileAllowList(t, r)

				_, ok := enforcedAllowList(t, cl)
				require.False(t, ok)
			})
		}
	}
}

// Allow lists which get changed without being enforced, and then changed
// back, get enforced again.
func TestReconcileAllowListRevertedChange(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Spec.Security.AllowedSyscalls = []string{"read"}

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})
	require.NoError(t, reconcileAllowList(t, r))

	_, ok := enforcedAllowList(t, cl)
	require.True(t, ok)

	update := func(security spodapi.SPODSecurityConfig) {
		t.Helper()

		current := &spodapi.SecurityProfilesOperatorDaemon{}
		require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(spod), current))
		current.Spec.Security = security
		require.NoError(t, cl.Update(t.Context(), current))
		require.NoError(t, reconcileAllowList(t, r))
	}

	update(spodapi.SPODSecurityConfig{
		AllowedSyscalls:       []string{"read"},
		AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActErrno},
	})

	require.NoError(t, cl.Create(t.Context(), allowListProfile("created-later", "", "write")))

	update(spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}})
	require.Empty(t, remainingProfiles(t, cl))
}

// The allow lists which get enforced are the ones the hash is computed of,
// also if they change while the hash of the ones enforced before gets
// removed, which reads the SPOD back.
func TestReconcileAllowListChangedDuringReconcile(t *testing.T) {
	t.Parallel()

	allowed := []string{"read"}

	spod := testSPOD()
	spod.Spec.Security.AllowedSyscalls = allowed
	spod.Annotations = map[string]string{
		enforcedAllowListAnnotation: allowListHash(&spodapi.SPODSecurityConfig{
			AllowedSyscalls: []string{"exit"},
		}),
	}

	patched := false
	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{
		Patch: func(
			ctx context.Context, c client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			if !patched {
				patched = true

				current := &spodapi.SecurityProfilesOperatorDaemon{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), current))
				current.Spec.Security.AllowedSyscalls = []string{"read", "write"}
				require.NoError(t, c.Update(ctx, current))
			}

			return c.Patch(ctx, obj, patch, opts...)
		},
	}, allowListProfile("forbidden", "", "read", "write"))

	require.NoError(t, reconcileAllowList(t, r))
	require.True(t, patched)

	// The change gets reverted before its own reconcile.
	current := &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(spod), current))
	current.Spec.Security.AllowedSyscalls = allowed
	require.NoError(t, cl.Update(t.Context(), current))
	require.NoError(t, reconcileAllowList(t, r))

	require.Empty(t, remainingProfiles(t, cl))
}

func TestAllowListHash(t *testing.T) {
	t.Parallel()

	require.Empty(t, allowListHash(&spodapi.SPODSecurityConfig{
		AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActLog},
	}))

	hash := allowListHash(&spodapi.SPODSecurityConfig{
		AllowedSyscalls:       []string{"read", "write"},
		AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActLog},
	})
	require.NotEmpty(t, hash)
	require.Equal(t, hash, allowListHash(&spodapi.SPODSecurityConfig{
		AllowedSyscalls: []string{"write", "read", "read"},
		AllowedSeccompActions: []seccompprofileapi.Action{
			seccompprofileapi.ActLog, seccompprofileapi.ActLog,
		},
	}))
	require.NotEqual(t, hash, allowListHash(&spodapi.SPODSecurityConfig{
		AllowedSyscalls: []string{"read", "write"},
	}))
	require.NotEqual(t, hash, allowListHash(&spodapi.SPODSecurityConfig{
		AllowedSyscalls:       []string{"read"},
		AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActLog},
	}))
}

func TestRejectedByAllowLists(t *testing.T) {
	t.Parallel()

	// The default action of the log enricher profile lets every syscall run
	// and logs it.
	profile := bindata.DefaultLogEnricherProfile()

	for name, tc := range map[string]struct {
		security spodapi.SPODSecurityConfig
		want     bool
	}{
		"no allow lists": {},
		"logged syscalls checked by default": {
			security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}},
			want:     true,
		},
		"logged syscalls not checked": {
			security: spodapi.SPODSecurityConfig{
				AllowedSyscalls:       []string{"read"},
				AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActAllow},
			},
		},
		"invalid allowed actions": {
			security: spodapi.SPODSecurityConfig{
				AllowedSyscalls:       []string{"read"},
				AllowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActErrno},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, rejectedByAllowLists(profile, &tc.security))
		})
	}
}
