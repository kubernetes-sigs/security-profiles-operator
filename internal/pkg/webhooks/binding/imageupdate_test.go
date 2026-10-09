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
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding/bindingfakes"
)

func newTestImageUpdateValidator(t *testing.T, mock *bindingfakes.FakeImpl) *imageUpdateValidator {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	return &imageUpdateValidator{
		binder:  &podBinder{impl: mock, log: logr.Discard(), operatorNamespace: "spo"},
		decoder: admission.NewDecoder(scheme),
		log:     logr.Discard(),
	}
}

// Bindings only apply on pod creation, so changing the image of a running pod
// used to restart its container with the image of a binding but without the
// bound profile.
func TestImageUpdateValidator(t *testing.T) {
	t.Parallel()

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "init", Image: "busybox"}},
			Containers: []corev1.Container{
				{Name: "app", Image: "unbound"},
				{Name: "bound", Image: "docker.io/library/nginx:1.23.2"},
			},
		},
	}

	for _, tc := range []struct {
		name     string
		bindings []profilebindingapi.ProfileBinding
		mutate   func(*corev1.Pod)
		allowed  bool
	}{
		{
			name:     "unchanged images",
			bindings: []profilebindingapi.ProfileBinding{seccompBinding("b", "p", "unbound", 1)},
			mutate:   func(p *corev1.Pod) { p.Labels = map[string]string{"a": "b"} },
			allowed:  true,
		},
		{
			name:     "no binding matches",
			bindings: []profilebindingapi.ProfileBinding{seccompBinding("b", "p", "other", 1)},
			mutate:   func(p *corev1.Pod) { p.Spec.Containers[0].Image = "unbound:2" },
			allowed:  true,
		},
		{
			name: "wildcard bindings apply independent of the image",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("b", "p", profilebindingapi.SelectAllContainersImage, 1),
			},
			mutate:  func(p *corev1.Pod) { p.Spec.Containers[0].Image = "unbound:2" },
			allowed: true,
		},
		{
			name:     "new image is bound",
			bindings: []profilebindingapi.ProfileBinding{seccompBinding("b", "p", "nginx:1.23.2", 1)},
			mutate:   func(p *corev1.Pod) { p.Spec.Containers[0].Image = "nginx:1.23.2" },
		},
		{
			name: "new image is bound in another notation",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("b", "p", "docker.io/library/nginx:1.23.2", 1),
			},
			mutate: func(p *corev1.Pod) { p.Spec.InitContainers[0].Image = "nginx:1.23.2" },
		},
		{
			name:     "old image is bound",
			bindings: []profilebindingapi.ProfileBinding{seccompBinding("b", "p", "nginx:1.23.2", 1)},
			mutate:   func(p *corev1.Pod) { p.Spec.Containers[1].Image = "unbound" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bindingfakes.FakeImpl{}
			mock.ListProfileBindingsReturns(
				&profilebindingapi.ProfileBindingList{Items: tc.bindings}, nil,
			)
			mock.GetSeccompProfileReturns(installedSeccompProfile("operator/p.json"), nil)

			pod := oldPod.DeepCopy()
			tc.mutate(pod)

			resp := newTestImageUpdateValidator(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					Namespace: "ns",
					Object:    rawObject(t, pod),
					OldObject: rawObject(t, oldPod),
				},
			})
			require.Equal(t, tc.allowed, resp.Allowed, resp.Result.Message)

			if !tc.allowed {
				require.Equal(t, http.StatusForbidden, int(resp.Result.Code))
				require.Contains(t, resp.Result.Message, "profile binding b")
			}
		})
	}
}

func TestImageUpdateValidatorSkipsOtherRequests(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{seccompBinding("b", "p", "bound", 1)},
	}, nil)
	mock.GetSeccompProfileReturns(installedSeccompProfile("operator/p.json"), nil)
	validator := newTestImageUpdateValidator(t, mock)

	oldPod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "unbound"},
	}}}
	pod := oldPod.DeepCopy()
	pod.Spec.Containers[0].Image = "bound"

	windowsPod := pod.DeepCopy()
	windowsPod.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
	oldWindowsPod := oldPod.DeepCopy()
	oldWindowsPod.Spec.OS = &corev1.PodOS{Name: corev1.Windows}

	for name, req := range map[string]admissionv1.AdmissionRequest{
		"create": {Operation: admissionv1.Create, Object: rawObject(t, pod)},
		"sub resource": {
			Operation:   admissionv1.Update,
			SubResource: "ephemeralcontainers",
			Object:      rawObject(t, pod),
			OldObject:   rawObject(t, oldPod),
		},
		"windows pod": {
			Operation: admissionv1.Update,
			Object:    rawObject(t, windowsPod),
			OldObject: rawObject(t, oldWindowsPod),
		},
	} {
		resp := validator.Handle(t.Context(), admission.Request{AdmissionRequest: req})
		require.True(t, resp.Allowed, name)
	}

	require.Zero(t, mock.ListProfileBindingsCallCount())

	// The same update of a Linux pod gets rejected.
	resp := validator.Handle(
		t.Context(),
		admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    rawObject(t, pod),
			OldObject: rawObject(t, oldPod),
		}},
	)
	require.False(t, resp.Allowed)
}

// The mutating webhook skips bindings to missing profiles and to profiles of
// disabled kinds which never get installed, so they apply to no pod and do
// not block image changes.
func TestImageUpdateValidatorIgnoresBindingsWhichApplyToNoPod(t *testing.T) {
	t.Parallel()

	appArmorBinding := seccompBinding("b", "p", "nginx:1.23.2", 1)
	appArmorBinding.Spec.ProfileRef.Kind = profilebindingapi.ProfileBindingKindAppArmorProfile

	oldPod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "nginx:1.23.2"},
	}}}
	pod := oldPod.DeepCopy()
	pod.Spec.Containers[0].Image = "nginx:1.24"

	for _, tc := range []struct {
		name    string
		binding profilebindingapi.ProfileBinding
		mock    func(*bindingfakes.FakeImpl)
		allowed bool
		errored bool
	}{
		{
			name:    "missing profile",
			binding: seccompBinding("b", "p", "nginx:1.23.2", 1),
			mock: func(mock *bindingfakes.FakeImpl) {
				mock.GetSeccompProfileReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, "p"))
			},
			allowed: true,
		},
		{
			name:    "profile without status of a disabled kind",
			binding: appArmorBinding,
			mock: func(mock *bindingfakes.FakeImpl) {
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)
			},
			allowed: true,
		},
		{
			name:    "profile without status of an enabled kind",
			binding: appArmorBinding,
			mock: func(mock *bindingfakes.FakeImpl) {
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{EnableAppArmor: new(true)},
				}, nil)
			},
		},
		{
			name:    "lookup error",
			binding: seccompBinding("b", "p", "nginx:1.23.2", 1),
			mock: func(mock *bindingfakes.FakeImpl) {
				mock.GetSeccompProfileReturns(nil, errTest)
			},
			errored: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bindingfakes.FakeImpl{}
			mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
				Items: []profilebindingapi.ProfileBinding{tc.binding},
			}, nil)
			tc.mock(mock)

			resp := newTestImageUpdateValidator(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					Namespace: "ns",
					Object:    rawObject(t, pod),
					OldObject: rawObject(t, oldPod),
				},
			})
			require.Equal(t, tc.allowed, resp.Allowed, resp.Result.Message)

			switch {
			case tc.errored:
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			case !tc.allowed:
				require.Equal(t, http.StatusForbidden, int(resp.Result.Code))
			}
		})
	}
}
