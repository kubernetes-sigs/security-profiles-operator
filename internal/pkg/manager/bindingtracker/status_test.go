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

package bindingtracker

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func TestBindingStatusReportsProfile(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		kind        profilebindingapi.ProfileBindingKind
		objs        []client.Object
		wantReason  common.ConditionReason
		wantRequeue bool
	}{
		"seccomp profile exists": {
			kind:       profilebindingapi.ProfileBindingKindSeccompProfile,
			objs:       []client.Object{&seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile"}}},
			wantReason: common.ReasonAvailable,
		},
		"selinux profile exists": {
			kind:       profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs:       []client.Object{&selinuxprofileapi.SelinuxProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile"}}},
			wantReason: common.ReasonAvailable,
		},
		"apparmor profile exists": {
			kind:       profilebindingapi.ProfileBindingKindAppArmorProfile,
			objs:       []client.Object{&apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile"}}},
			wantReason: common.ReasonAvailable,
		},
		"profile missing": {
			kind:        profilebindingapi.ProfileBindingKindSeccompProfile,
			wantReason:  common.ReasonUnavailable,
			wantRequeue: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			scheme := newTestScheme(t)
			require.NoError(t, seccompprofileapi.AddToScheme(scheme))
			require.NoError(t, selinuxprofileapi.AddToScheme(scheme))
			require.NoError(t, apparmorprofileapi.AddToScheme(scheme))

			binding := &profilebindingapi.ProfileBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default", Generation: 2},
				Spec: profilebindingapi.ProfileBindingSpec{
					ProfileRef: profilebindingapi.ProfileRef{Kind: tc.kind, Name: "profile"},
					Image:      "nginx",
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(binding).
				WithObjects(append(tc.objs, binding)...).
				Build()

			r := &bindingStatusReconciler{client: c, reader: c, log: logr.Discard()}

			res, err := r.Reconcile(t.Context(), reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(binding),
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantRequeue, res.RequeueAfter > 0)

			updated := &profilebindingapi.ProfileBinding{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))

			ready := updated.Status.GetReadyCondition()
			require.Equal(t, string(tc.wantReason), ready.Reason)
			require.Equal(t, updated.Generation, ready.ObservedGeneration)
		})
	}
}

func TestBindingStatusIgnoresMissingBinding(t *testing.T) {
	t.Parallel()

	c := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	r := &bindingStatusReconciler{client: c, reader: c, log: logr.Discard()}

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "gone"},
	})
	require.NoError(t, err)
}

func TestBindingRequestsForProfile(t *testing.T) {
	t.Parallel()

	binding := func(name string, kind profilebindingapi.ProfileBindingKind) *profilebindingapi.ProfileBinding {
		return &profilebindingapi.ProfileBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{Kind: kind, Name: "profile"},
				Image:      "nginx",
			},
		}
	}

	c := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(
			binding("seccomp", profilebindingapi.ProfileBindingKindSeccompProfile),
			binding("selinux", profilebindingapi.ProfileBindingKindSelinuxProfile),
		).
		WithIndex(&profilebindingapi.ProfileBinding{}, profileRefKey, profileRefIndex).
		Build()

	r := &bindingStatusReconciler{client: c, reader: c, log: logr.Discard()}

	// A deleted profile enqueues the bindings of its kind which refer to it.
	requests := r.bindingRequests(profilebindingapi.ProfileBindingKindSeccompProfile)(
		t.Context(),
		&seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile"}},
	)
	require.Equal(t, []reconcile.Request{{
		NamespacedName: client.ObjectKey{Namespace: "default", Name: "seccomp"},
	}}, requests)

	require.Empty(t, r.bindingRequests(profilebindingapi.ProfileBindingKindAppArmorProfile)(
		t.Context(),
		&apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{Name: "profile"}},
	))
}
