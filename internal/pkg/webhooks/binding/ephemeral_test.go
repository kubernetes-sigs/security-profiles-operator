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

package binding

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding/bindingfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

func rawObject(t *testing.T, obj any) runtime.RawExtension {
	t.Helper()

	b, err := json.Marshal(obj)
	require.NoError(t, err)

	return runtime.RawExtension{Raw: b}
}

func installedSeccompProfile(localhostProfile string) *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		Status: seccompprofileapi.SeccompProfileStatus{
			StatusBase: profilebaseapi.StatusBase{
				Status: secprofnodestatusapi.ProfileStateInstalled,
			},
			LocalhostProfile: localhostProfile,
		},
	}
}

// Ephemeral containers are added to running pods through a sub resource. They
// used to escape all bindings, so a debug container could run unconfined in a
// namespace with enforced profiles.
func TestUpdatePodEphemeralContainers(t *testing.T) {
	t.Parallel()

	const (
		boundSeccomp    = "operator/debug.json"
		wildcardSelinux = "wildcard_type.process"
	)

	bindings := []profilebindingapi.ProfileBinding{
		{
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
					Name: "debug",
				},
				Image: "debug",
			},
		},
		{
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
					Name: "wildcard",
				},
				Image: profilebindingapi.SelectAllContainersImage,
			},
		},
	}

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileReturns(installedSeccompProfile(boundSeccomp), nil)
	mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
		Status: selinuxprofileapi.SelinuxProfileStatus{
			StatusBase: profilebaseapi.StatusBase{
				Status: secprofnodestatusapi.ProfileStateInstalled,
			},
			Usage: wildcardSelinux,
		},
	}, nil)

	ephemeral := func(name, image string, sc *corev1.SecurityContext) corev1.EphemeralContainer {
		return corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: name, Image: image, SecurityContext: sc,
			},
		}
	}

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "app"}},
			EphemeralContainers: []corev1.EphemeralContainer{
				ephemeral("existing", "debug", nil),
			},
		},
	}

	newPod := oldPod.DeepCopy()
	newPod.Spec.EphemeralContainers = append(newPod.Spec.EphemeralContainers,
		ephemeral("new-debug", "debug", nil),
		ephemeral("other", "busybox", &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
		}),
	)

	binder := newTestBinder(t, mock)
	pod, resp := binder.updatePod(t.Context(), bindings, &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation:   admissionv1.Update,
			SubResource: ephemeralContainersSubResource,
			Object:      rawObject(t, newPod),
			OldObject:   rawObject(t, oldPod),
		},
	})
	require.Equal(t, admission.Response{}, resp)

	// The pod security context and existing containers cannot be changed.
	require.Nil(t, pod.Spec.SecurityContext)
	require.Nil(t, pod.Spec.Containers[0].SecurityContext)
	require.Nil(t, pod.Spec.EphemeralContainers[0].SecurityContext)

	boundProfile := boundSeccomp
	require.Equal(t,
		&corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{
				Type:             corev1.SeccompProfileTypeLocalhost,
				LocalhostProfile: &boundProfile,
			},
			SELinuxOptions: &corev1.SELinuxOptions{Type: wildcardSelinux},
		},
		pod.Spec.EphemeralContainers[1].SecurityContext,
	)

	// Wildcard bindings apply to every new ephemeral container, because the
	// pod level value may be missing if the pod predates the binding.
	require.Equal(t,
		&corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
			SELinuxOptions: &corev1.SELinuxOptions{Type: wildcardSelinux},
		},
		pod.Spec.EphemeralContainers[2].SecurityContext,
	)
}

func TestHandleEphemeralContainersPatch(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{{
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				},
				Image: profilebindingapi.SelectAllContainersImage,
			},
		}},
	}, nil)
	mock.GetSeccompProfileReturns(installedSeccompProfile("operator/wildcard.json"), nil)

	oldPod := &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app"}}},
	}
	newPod := oldPod.DeepCopy()
	newPod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "debug"},
	}}

	resp := newTestBinder(t, mock).Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation:   admissionv1.Update,
			SubResource: ephemeralContainersSubResource,
			Object:      rawObject(t, newPod),
			OldObject:   rawObject(t, oldPod),
		},
	})

	require.True(t, resp.Allowed)
	require.Len(t, resp.Patches, 1)
	require.Equal(t, "/spec/ephemeralContainers/0/securityContext", resp.Patches[0].Path)
}

// Other pod updates, including other sub resources, cannot change the security
// context and must not be mutated.
func TestUpdatePodSkipsOtherUpdates(t *testing.T) {
	t.Parallel()

	for _, subResource := range []string{"", "status", "resize"} {
		mock := &bindingfakes.FakeImpl{}
		_, resp := newTestBinder(t, mock).updatePod(t.Context(), nil, &admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation:   admissionv1.Update,
				SubResource: subResource,
			},
		})

		require.True(t, resp.Allowed, subResource)
		require.Equal(t, "pod update, skipping mutation", resp.Result.Message, subResource)
	}
}

// A binding to a profile without status blocks the pods for good when the SPOD
// does not enable the profile kind, because no daemon ever reports a status.
// Only for disabled kinds the binding gets skipped, immediately and without
// retries, and the user gets notified. This uses a live context, because the
// lookup retries used to exhaust it before the SPOD got read.
func TestUpdatePodProfileWithoutStatusRecordsEvent(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{}, nil)
	mock.GetSPODCalls(func(ctx context.Context, _ types.NamespacedName) (
		*spodapi.SecurityProfilesOperatorDaemon, error,
	) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		return &spodapi.SecurityProfilesOperatorDaemon{}, nil
	})

	recorder := events.NewFakeRecorder(1)
	binder := newTestBinder(t, mock)
	binder.record = utils.NewSafeRecorder(recorder)

	start := time.Now()
	pod, resp := binder.updatePod(t.Context(), []profilebindingapi.ProfileBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "binding"},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
				Name: "profile",
			},
			Image: "foo",
		},
	}}, &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    rawObject(t, testPod),
		},
	})

	require.True(t, resp.Allowed)
	require.Equal(t, "pod unchanged", resp.Result.Message)
	require.Nil(t, pod.Spec.Containers[0].SecurityContext)
	require.Contains(t, <-recorder.Events, reasonProfileWithoutStatus)
	require.Equal(t, 1, mock.GetAppArmorProfileCallCount())
	require.Equal(t, 1, mock.GetSPODCallCount())
	require.Less(t, time.Since(start), time.Second, "disabled kinds must not be retried")
}

// Profiles of enabled kinds without status are retried within the lookup
// budget and then rejected, so the pod does not run without its profile.
func TestUpdatePodEnabledProfileWithoutStatusRejects(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{}, nil)
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{EnableAppArmor: new(true)},
	}, nil)

	binding := profilebindingapi.ProfileBinding{Spec: profilebindingapi.ProfileBindingSpec{
		ProfileRef: profilebindingapi.ProfileRef{
			Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
			Name: "profile",
		},
		Image: "foo",
	}}

	start := time.Now()
	_, resp := newTestBinder(t, mock).updatePod(
		t.Context(),
		[]profilebindingapi.ProfileBinding{binding, binding},
		&admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    rawObject(t, testPod),
		}},
	)

	require.False(t, resp.Allowed)
	require.Equal(t, int32(http.StatusInternalServerError), resp.Result.Code)
	require.Greater(t, mock.GetAppArmorProfileCallCount(), 1, "the lookup must be retried")
	require.Equal(t, 1, mock.GetSPODCallCount(), "the SPOD is read once per request")

	// The static webhook configuration uses a timeout of five seconds.
	require.Less(t, time.Since(start), profileLookupTimeout+time.Second)
}

// A request context which is done while reading the SPOD must not be mistaken
// for a disabled kind.
func TestUpdatePodSPODContextDone(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{}, nil)
	mock.GetSPODCalls(func(ctx context.Context, _ types.NamespacedName) (
		*spodapi.SecurityProfilesOperatorDaemon, error,
	) {
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, resp := newTestBinder(t, mock).updatePod(ctx, []profilebindingapi.ProfileBinding{{
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
				Name: "profile",
			},
			Image: "foo",
		},
	}}, &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Object:    rawObject(t, testPod),
	}})

	require.False(t, resp.Allowed)
	require.Equal(t, int32(http.StatusInternalServerError), resp.Result.Code)
	require.Zero(t, mock.GetAppArmorProfileCallCount())
}

// Bindings to profiles of enabled kinds without status are rejected, because
// the pod would otherwise run without the profile until a daemon installed it.
func TestProfileKindEnabled(t *testing.T) {
	t.Parallel()

	selinux := profilebindingapi.ProfileBindingKindSelinuxProfile
	apparmor := profilebindingapi.ProfileBindingKindAppArmorProfile

	for _, tc := range []struct {
		name        string
		kind        profilebindingapi.ProfileBindingKind
		spod        *spodapi.SecurityProfilesOperatorDaemon
		spodErr     error
		isOpenShift bool
		enabled     bool
		wantErr     bool
	}{
		{name: "seccomp", kind: profilebindingapi.ProfileBindingKindSeccompProfile, enabled: true},
		{name: "apparmor disabled", kind: apparmor, spod: &spodapi.SecurityProfilesOperatorDaemon{}},
		{
			name: "apparmor enabled", kind: apparmor, enabled: true,
			spod: &spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{EnableAppArmor: new(true)},
			},
		},
		{name: "selinux default", kind: selinux, spod: &spodapi.SecurityProfilesOperatorDaemon{}},
		{
			name: "selinux default on openshift", kind: selinux, isOpenShift: true, enabled: true,
			spod: &spodapi.SecurityProfilesOperatorDaemon{},
		},
		{
			name: "selinux disabled on openshift", kind: selinux, isOpenShift: true,
			spod: &spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{Selinux: spodapi.SPODSelinuxConfig{Enable: new(false)}},
			},
		},
		{
			name: "missing spod", kind: apparmor, enabled: true,
			spodErr: kerrors.NewNotFound(schema.GroupResource{}, "spod"),
		},
		{name: "spod error", kind: apparmor, spodErr: errTest, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bindingfakes.FakeImpl{}
			mock.GetSPODReturns(tc.spod, tc.spodErr)

			binder := newTestBinder(t, mock)
			binder.isOpenShift = tc.isOpenShift

			enabled, err := binder.profileKindEnabled(t.Context(), tc.kind)
			if tc.wantErr {
				require.ErrorIs(t, err, errTest)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.enabled, enabled)
		})
	}
}

func TestRetryProfileLookup(t *testing.T) {
	t.Parallel()

	t.Run("retries until the profile got a status", func(t *testing.T) {
		t.Parallel()

		calls := 0
		err := retryProfileLookup(t.Context(), true, func() error {
			calls++
			if calls < 2 {
				return ErrProfWithoutStatus
			}

			return nil
		})

		require.NoError(t, err)
		require.Equal(t, 2, calls)
	})

	t.Run("does not retry other errors", func(t *testing.T) {
		t.Parallel()

		calls := 0
		err := retryProfileLookup(t.Context(), true, func() error {
			calls++

			return errTest
		})

		require.ErrorIs(t, err, errTest)
		require.Equal(t, 1, calls)
	})

	t.Run("runs once without retry", func(t *testing.T) {
		t.Parallel()

		calls := 0
		err := retryProfileLookup(t.Context(), false, func() error {
			calls++

			return ErrProfWithoutStatus
		})

		require.ErrorIs(t, err, ErrProfWithoutStatus)
		require.Equal(t, 1, calls)
	})

	t.Run("stops when the context is done", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()

		start := time.Now()
		err := retryProfileLookup(ctx, true, func() error { return ErrProfWithoutStatus })

		require.ErrorIs(t, err, ErrProfWithoutStatus)
		require.Less(t, time.Since(start), time.Second)
	})
}

func TestGetProfileUnsupportedKind(t *testing.T) {
	t.Parallel()

	profile, skip, err := newTestBinder(t, &bindingfakes.FakeImpl{}).getProfile(
		t.Context(),
		&profileLookup{
			retryDeadline: time.Now(),
			enabled:       map[profilebindingapi.ProfileBindingKind]bool{},
		},
		&profilebindingapi.ProfileBinding{
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{Kind: "Unknown"},
			},
		},
		"ns",
	)

	require.NoError(t, err)
	require.True(t, skip)
	require.Nil(t, profile)
}
