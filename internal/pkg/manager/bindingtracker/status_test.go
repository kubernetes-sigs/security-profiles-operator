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
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func TestBindingStatusReportsProfile(t *testing.T) {
	t.Parallel()

	installed := profilebasev1.StatusBase{Status: secprofnodestatusapi.ProfileStateInstalled}
	meta := metav1.ObjectMeta{Name: "profile"}
	spod := func(mutate func(*spodapi.SecurityProfilesOperatorDaemon)) *spodapi.SecurityProfilesOperatorDaemon {
		s := &spodapi.SecurityProfilesOperatorDaemon{
			ObjectMeta: metav1.ObjectMeta{Name: config.SPOdName, Namespace: "operator"},
		}
		mutate(s)

		return s
	}

	for name, tc := range map[string]struct {
		kind        profilebindingapi.ProfileBindingKind
		objs        []client.Object
		podSelector *metav1.LabelSelector
		isOpenShift bool
		wantReason  common.ConditionReason
		wantMessage string
	}{
		"seccomp profile installed": {
			kind: profilebindingapi.ProfileBindingKindSeccompProfile,
			objs: []client.Object{&seccompprofileapi.SeccompProfile{
				ObjectMeta: meta, Status: seccompprofileapi.SeccompProfileStatus{StatusBase: installed},
			}},
			wantReason: common.ReasonAvailable,
		},
		"selinux profile installed": {
			kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs: []client.Object{&selinuxprofileapi.SelinuxProfile{
				ObjectMeta: meta, Status: selinuxprofileapi.SelinuxProfileStatus{StatusBase: installed},
			}},
			wantReason: common.ReasonAvailable,
		},
		"apparmor profile installed": {
			kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
			objs: []client.Object{&apparmorprofileapi.AppArmorProfile{
				ObjectMeta: meta, Status: apparmorprofileapi.AppArmorProfileStatus{StatusBase: installed},
			}},
			wantReason: common.ReasonAvailable,
		},
		"profile missing": {
			kind:       profilebindingapi.ProfileBindingKindSeccompProfile,
			wantReason: common.ReasonUnavailable,
		},
		"profile pending": {
			kind: profilebindingapi.ProfileBindingKindSeccompProfile,
			objs: []client.Object{&seccompprofileapi.SeccompProfile{
				ObjectMeta: meta, Status: seccompprofileapi.SeccompProfileStatus{
					StatusBase: profilebasev1.StatusBase{Status: secprofnodestatusapi.ProfileStatePending},
				},
			}},
			wantReason:  profilebindingapi.ReasonProfileNotInstalled,
			wantMessage: "SeccompProfile profile is not installed, its status is Pending",
		},
		"profile in error": {
			kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
			objs: []client.Object{&apparmorprofileapi.AppArmorProfile{
				ObjectMeta: meta, Status: apparmorprofileapi.AppArmorProfileStatus{
					StatusBase: profilebasev1.StatusBase{Status: secprofnodestatusapi.ProfileStateError},
				},
			}},
			wantReason:  profilebindingapi.ReasonProfileNotInstalled,
			wantMessage: "AppArmorProfile profile is not installed, its status is Error",
		},
		"profile without status": {
			kind:       profilebindingapi.ProfileBindingKindSeccompProfile,
			objs:       []client.Object{&seccompprofileapi.SeccompProfile{ObjectMeta: meta}},
			wantReason: profilebindingapi.ReasonProfileNotInstalled,
		},
		"apparmor disabled": {
			kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
			objs: []client.Object{
				&apparmorprofileapi.AppArmorProfile{ObjectMeta: meta},
				spod(func(*spodapi.SecurityProfilesOperatorDaemon) {}),
			},
			wantReason: profilebindingapi.ReasonProfileKindDisabled,
		},
		"apparmor enabled": {
			kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
			objs: []client.Object{
				&apparmorprofileapi.AppArmorProfile{ObjectMeta: meta},
				spod(func(s *spodapi.SecurityProfilesOperatorDaemon) { s.Spec.EnableAppArmor = new(true) }),
			},
			wantReason: profilebindingapi.ReasonProfileNotInstalled,
		},
		"selinux disabled": {
			kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs: []client.Object{
				&selinuxprofileapi.SelinuxProfile{ObjectMeta: meta},
				spod(func(s *spodapi.SecurityProfilesOperatorDaemon) { s.Spec.Selinux.Enable = new(false) }),
			},
			wantReason: profilebindingapi.ReasonProfileKindDisabled,
		},
		// SELinux is enabled by default only on OpenShift.
		"selinux unset": {
			kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs: []client.Object{
				&selinuxprofileapi.SelinuxProfile{ObjectMeta: meta},
				spod(func(*spodapi.SecurityProfilesOperatorDaemon) {}),
			},
			wantReason: profilebindingapi.ReasonProfileKindDisabled,
		},
		"selinux unset on OpenShift": {
			kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs: []client.Object{
				&selinuxprofileapi.SelinuxProfile{ObjectMeta: meta},
				spod(func(*spodapi.SecurityProfilesOperatorDaemon) {}),
			},
			isOpenShift: true,
			wantReason:  profilebindingapi.ReasonProfileNotInstalled,
		},
		"selinux disabled on OpenShift": {
			kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs: []client.Object{
				&selinuxprofileapi.SelinuxProfile{ObjectMeta: meta},
				spod(func(s *spodapi.SecurityProfilesOperatorDaemon) { s.Spec.Selinux.Enable = new(false) }),
			},
			isOpenShift: true,
			wantReason:  profilebindingapi.ReasonProfileKindDisabled,
		},
		"selinux enabled": {
			kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs: []client.Object{
				&selinuxprofileapi.SelinuxProfile{ObjectMeta: meta},
				spod(func(s *spodapi.SecurityProfilesOperatorDaemon) { s.Spec.Selinux.Enable = new(true) }),
			},
			wantReason: profilebindingapi.ReasonProfileNotInstalled,
		},
		// The webhook skips a binding with an invalid selector for every pod,
		// also if its profile is installed.
		"invalid pod selector": {
			kind: profilebindingapi.ProfileBindingKindSeccompProfile,
			objs: []client.Object{&seccompprofileapi.SeccompProfile{
				ObjectMeta: meta, Status: seccompprofileapi.SeccompProfileStatus{StatusBase: installed},
			}},
			podSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"in valid": "app"}},
			wantReason:  profilebindingapi.ReasonInvalidPodSelector,
		},
		// Like for the webhook, a missing configuration counts as enabled.
		"selinux without SPOD": {
			kind:       profilebindingapi.ProfileBindingKindSelinuxProfile,
			objs:       []client.Object{&selinuxprofileapi.SelinuxProfile{ObjectMeta: meta}},
			wantReason: profilebindingapi.ReasonProfileNotInstalled,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			scheme := utiltest.NewScheme(t)
			require.NoError(t, seccompprofileapi.AddToScheme(scheme))
			require.NoError(t, selinuxprofileapi.AddToScheme(scheme))
			require.NoError(t, apparmorprofileapi.AddToScheme(scheme))
			require.NoError(t, spodapi.AddToScheme(scheme))

			binding := &profilebindingapi.ProfileBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default", Generation: 2},
				Spec: profilebindingapi.ProfileBindingSpec{
					ProfileRef:  profilebindingapi.ProfileRef{Kind: tc.kind, Name: "profile"},
					Image:       "nginx",
					PodSelector: tc.podSelector,
				},
				Status: profilebindingapi.ProfileBindingStatus{
					ActiveWorkloads: []string{"default/pod"},
				},
			}

			statusUpdates := 0
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(binding).
				WithObjects(append(tc.objs, binding)...).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceUpdate: func(
						ctx context.Context, cl client.Client, sub string, obj client.Object,
						opts ...client.SubResourceUpdateOption,
					) error {
						statusUpdates++

						return cl.SubResource(sub).Update(ctx, obj, opts...)
					},
				}).
				Build()

			r := &bindingStatusReconciler{
				client: c, reader: c, log: logr.Discard(), operatorNamespace: "operator",
				isOpenShift: tc.isOpenShift,
			}

			res, err := r.Reconcile(t.Context(), reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(binding),
			})
			require.NoError(t, err)
			require.Zero(t, res)

			updated := &profilebindingapi.ProfileBinding{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(binding), updated))

			ready := updated.Status.GetReadyCondition()
			require.Equal(t, string(tc.wantReason), ready.Reason)
			require.Equal(t, updated.Generation, ready.ObservedGeneration)

			if tc.wantMessage != "" {
				require.Equal(t, tc.wantMessage, ready.Message)
			}

			// Only the condition gets patched.
			require.Zero(t, statusUpdates)
			require.Equal(t, []string{"default/pod"}, updated.Status.ActiveWorkloads)
		})
	}
}

// A binding whose cached condition is current costs no read from the API
// server, which every binding reconciled on startup and every requeue of a
// binding to a missing profile would otherwise do.
func TestBindingStatusReadsCacheFirst(t *testing.T) {
	t.Parallel()

	binding := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile, Name: "profile",
			},
			Image: "nginx",
		},
	}

	scheme := utiltest.NewScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(binding).WithObjects(binding).Build()

	apiReads := 0
	reader := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, cl client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				apiReads++

				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()

	r := &bindingStatusReconciler{client: c, reader: reader, log: logr.Discard()}
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(binding)}

	// The first reconcile sets the condition, the second finds it set.
	for range 2 {
		_, err := r.Reconcile(t.Context(), req)
		require.NoError(t, err)
	}

	require.Zero(t, apiReads)

	updated := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), req.NamespacedName, updated))
	require.Equal(t, string(common.ReasonUnavailable), updated.Status.GetReadyCondition().Reason)
}

func TestProfileState(t *testing.T) {
	t.Parallel()

	sp := &seccompprofileapi.SeccompProfile{}
	sp.Status.Status = secprofnodestatusapi.ProfileStateInstalled
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, profileState(sp))
	require.Empty(t, profileState(&profilebindingapi.ProfileBinding{}))
}

func TestBindingStatusIgnoresMissingBinding(t *testing.T) {
	t.Parallel()

	c := fake.NewClientBuilder().WithScheme(utiltest.NewScheme(t)).Build()
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
		WithScheme(utiltest.NewScheme(t)).
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

	// A changed SPOD configuration can enable or disable the kind of every
	// profile.
	require.ElementsMatch(t, []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: "default", Name: "seccomp"}},
		{NamespacedName: client.ObjectKey{Namespace: "default", Name: "selinux"}},
	}, r.allBindings(t.Context(), nil))
}
