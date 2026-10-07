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
