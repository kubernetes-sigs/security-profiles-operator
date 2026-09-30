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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding/bindingfakes"
)

// The API server rejects security profiles on Windows pods, and the webhook
// fails closed, so binding them would reject every Windows pod.
func TestUpdatePodSkipsWindowsPods(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileReturns(installedSeccompProfile("operator/wildcard.json"), nil)

	pod := testPod.DeepCopy()
	pod.Spec.OS = &corev1.PodOS{Name: corev1.Windows}

	bindings := []profilebindingapi.ProfileBinding{{
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: "wildcard",
			},
			Image: profilebindingapi.SelectAllContainersImage,
		},
	}}

	_, warnings, resp := newTestBinder(t, mock).updatePod(t.Context(), bindings, &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    rawObject(t, pod),
		},
	})

	require.NotNil(t, resp)
	require.True(t, resp.Allowed)
	require.Equal(t, "windows pod, skipping mutation", resp.Result.Message)
	require.Empty(t, warnings)
	require.Equal(t, 0, mock.GetSeccompProfileCallCount())
}

// Profiles are cluster scoped, so the lookup key must not carry the namespace
// of the pod.
func TestGetProfileKeyWithoutNamespace(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileReturns(installedSeccompProfile("operator/profile.json"), nil)

	_, skip, err := newTestBinder(t, mock).getProfile(
		t.Context(),
		&profileLookup{
			retryDeadline: time.Now(),
			enabled:       map[profilebindingapi.ProfileBindingKind]bool{},
		},
		&profilebindingapi.ProfileBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns"},
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
					Name: "profile",
				},
			},
		},
	)
	require.NoError(t, err)
	require.False(t, skip)
	require.Equal(t, 1, mock.GetSeccompProfileCallCount())

	_, key := mock.GetSeccompProfileArgsForCall(0)
	require.Equal(t, types.NamespacedName{Name: "profile"}, key)
}

func TestSortBindings(t *testing.T) {
	t.Parallel()

	binding := func(name string, created int64) profilebindingapi.ProfileBinding {
		return profilebindingapi.ProfileBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				CreationTimestamp: metav1.Unix(created, 0),
			},
		}
	}

	sorted := sortBindings([]profilebindingapi.ProfileBinding{
		binding("b-newer", 20),
		binding("z-oldest", 10),
		binding("a-newer", 20),
		binding("m-newest", 30),
	})

	names := make([]string, 0, len(sorted))
	for _, pb := range sorted {
		names = append(names, pb.Name)
	}

	// Oldest first, the name breaks ties.
	require.Equal(t, []string{"z-oldest", "a-newer", "b-newer", "m-newest"}, names)
	require.Empty(t, sortBindings(nil))
}

func TestAddSeccompContext(t *testing.T) {
	t.Parallel()

	const bound = "operator/bound.json"

	profile := installedSeccompProfile(bound)
	boundProfile := bound
	want := &corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &boundProfile,
	}

	for _, tc := range []struct {
		name    string
		ctr     *corev1.Container
		changed bool
	}{
		{name: "no security context", ctr: &corev1.Container{}, changed: true},
		{
			name:    "no seccomp profile",
			ctr:     &corev1.Container{SecurityContext: &corev1.SecurityContext{}},
			changed: true,
		},
		{
			name: "unconfined is overwritten",
			ctr: &corev1.Container{SecurityContext: &corev1.SecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
			}},
			changed: true,
		},
		{
			name: "bound profile is kept",
			ctr: &corev1.Container{SecurityContext: &corev1.SecurityContext{
				SeccompProfile: want.DeepCopy(),
			}},
			changed: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			binder := newTestBinder(t, &bindingfakes.FakeImpl{})
			require.Equal(t, tc.changed, binder.addSeccompContext(tc.ctr, profile))
			require.Equal(t, want, tc.ctr.SecurityContext.SeccompProfile)
		})
	}
}

func TestSetSelinuxType(t *testing.T) {
	t.Parallel()

	const usage = "bound_t.process"

	t.Run("nil options", func(t *testing.T) {
		t.Parallel()

		var opts *corev1.SELinuxOptions

		require.True(t, setSelinuxType(&opts, usage))
		require.Equal(t, &corev1.SELinuxOptions{Type: usage}, opts)
	})

	t.Run("other type keeps the level", func(t *testing.T) {
		t.Parallel()

		opts := &corev1.SELinuxOptions{Type: "other_t", Level: "s0:c1,c2", User: "system_u"}

		require.True(t, setSelinuxType(&opts, usage))
		require.Equal(
			t,
			&corev1.SELinuxOptions{Type: usage, Level: "s0:c1,c2", User: "system_u"},
			opts,
		)
	})

	t.Run("same type is unchanged", func(t *testing.T) {
		t.Parallel()

		opts := &corev1.SELinuxOptions{Type: usage, Level: "s0"}

		require.False(t, setSelinuxType(&opts, usage))
		require.Equal(t, &corev1.SELinuxOptions{Type: usage, Level: "s0"}, opts)
	})
}

func TestAddSelinuxContext(t *testing.T) {
	t.Parallel()

	profile := &selinuxprofileapi.SelinuxProfile{
		Status: selinuxprofileapi.SelinuxProfileStatus{Usage: "bound_t.process"},
	}

	ctr := &corev1.Container{}
	binder := newTestBinder(t, &bindingfakes.FakeImpl{})

	require.True(t, binder.addSelinuxContext(ctr, profile))
	require.Equal(t, "bound_t.process", ctr.SecurityContext.SELinuxOptions.Type)
	require.False(t, binder.addSelinuxContext(ctr, profile))
}

func TestAddAppArmorContext(t *testing.T) {
	t.Parallel()

	profile := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "bound"},
	}
	profileName := profile.GetProfileName()
	want := &corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: &profileName,
	}

	for _, tc := range []struct {
		name    string
		ctr     *corev1.Container
		changed bool
	}{
		{name: "no security context", ctr: &corev1.Container{}, changed: true},
		{
			name: "unconfined is overwritten",
			ctr: &corev1.Container{SecurityContext: &corev1.SecurityContext{
				AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
			}},
			changed: true,
		},
		{
			name: "bound profile is kept",
			ctr: &corev1.Container{SecurityContext: &corev1.SecurityContext{
				AppArmorProfile: want.DeepCopy(),
			}},
			changed: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			binder := newTestBinder(t, &bindingfakes.FakeImpl{})
			require.Equal(t, tc.changed, binder.addAppArmorContext(tc.ctr, profile))
			require.Equal(t, want, tc.ctr.SecurityContext.AppArmorProfile)
		})
	}
}

func TestAddSecurityContextUnexpectedType(t *testing.T) {
	t.Parallel()

	ctr := &corev1.Container{}
	binder := newTestBinder(t, &bindingfakes.FakeImpl{})

	require.False(t, binder.addSecurityContext(ctr, "not a profile"))
	require.Nil(t, ctr.SecurityContext)
	require.False(t, binder.addPodSecurityContext(&corev1.Pod{}, "not a profile"))
}
