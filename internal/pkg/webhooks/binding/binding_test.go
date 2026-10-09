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
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"gomodules.xyz/jsonpatch/v2"
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
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding/bindingfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

var (
	errTest = errors.New("error")
	testPod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "pod-",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "container",
					Image: "foo",
				},
			},
		},
	}
	testPodWithLabels = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "pod-",
			Labels:       map[string]string{"app": "bar"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "container",
					Image: "foo",
				},
			},
		},
	}
)

func newTestBinder(t *testing.T, mock *bindingfakes.FakeImpl) *podBinder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	return &podBinder{
		impl:    mock,
		decoder: admission.NewDecoder(scheme),
		log:     logr.Discard(),
	}
}

func TestHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*bindingfakes.FakeImpl)
		request admission.Request
		assert  func(admission.Response)
	}{
		{
			name: "success pod unchanged",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    runtime.RawExtension{Raw: []byte("{}")},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, "pod unchanged", resp.Result.Message)
			},
		},
		{
			name: "success pod update skips mutation",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
				require.Equal(t, "pod update, skipping mutation", resp.Result.Message)
			},
		},
		{
			name: "error could not list profile bindings",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(nil, errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{
			name: "error failed to decode pod",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    runtime.RawExtension{Raw: []byte("{")},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		//nolint:dupl // test duplicates are fine
		{
			name: "success pod changed",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "success pod changed when podSelector matches",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "bar"},
								},
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPodWithLabels.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "success pod unchanged when podSelector does not match",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "other"},
								},
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPodWithLabels.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
				require.Equal(t, "pod unchanged", resp.Result.Message)
			},
		},
		//nolint:dupl // test duplicates are fine
		{
			name: "success pod changed with * image",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "success seccomp pod security context overwrite with * image",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
						LocalhostProfile: "seccomp-test-profile",
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							podWithSecurityContext := testPod.DeepCopy()
							podWithSecurityContext.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeUnconfined,
								},
							}
							b, err := json.Marshal(podWithSecurityContext)
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				// add the pod level profile, and replace the container level
				// profile
				require.Len(t, resp.Patches, 2)
			},
		},
		{
			name: "selinux success pod changed",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
					Status: selinuxprofileapi.SelinuxProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: "Installed",
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "success selinux pod security context overwrite with * image",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
					Status: selinuxprofileapi.SelinuxProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: "Installed",
						},
						Usage: "test-usage",
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							podWithSecurityContext := testPod.DeepCopy()
							podWithSecurityContext.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
								SELinuxOptions: &corev1.SELinuxOptions{
									Type: "unconfined",
								},
							}
							b, err := json.Marshal(podWithSecurityContext)
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 2)
			},
		},
		{
			name: "selinux success pod changed with * image",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
					Status: selinuxprofileapi.SelinuxProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: "Installed",
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		//nolint:dupl // test duplicates are fine
		{
			name: "apparmor success pod changed",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{
					Status: apparmorprofileapi.AppArmorProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "success apparmor security context overwritten with * image",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-apparmor-profile",
					},
					Status: apparmorprofileapi.AppArmorProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							podWithSecurityContext := testPod.DeepCopy()
							podWithSecurityContext.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
								AppArmorProfile: &corev1.AppArmorProfile{
									Type: corev1.AppArmorProfileTypeUnconfined,
								},
							}
							b, err := json.Marshal(podWithSecurityContext)
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				// the pod level profile and the container level profile
				require.Len(t, resp.Patches, 2)
			},
		},
		//nolint:dupl // test duplicates are fine
		{
			name: "apparmor success pod changed with * image",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{
					Status: apparmorprofileapi.AppArmorProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "failure get apparmor profile errored",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
								},
							},
						},
					},
				}, nil)
				mock.GetAppArmorProfileReturns(nil, errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{
			name: "success skip apparmor profile without status of a disabled kind",
			// No daemon reports a status if the SPOD does not enable the
			// profile kind, so rejecting the pod would block it forever.
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{
					Status: apparmorprofileapi.AppArmorProfileStatus{},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{
			name: "success unsupported kind",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: "unsupported",
								},
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{
			name: "failure seccomp profile without status",
			// Seccomp is always enabled, so the status is only missing until
			// a daemon installed the profile, and the pod must not run
			// without it in the meantime.
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
								Image: profilebindingapi.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusForbidden, int(resp.Result.Code))
			},
		},
		{
			name: "failure get seccomp profile errored",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
							},
						},
					},
				}, nil)
				mock.GetSeccompProfileReturns(nil, errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{
			name: "success when the profile referenced in the profile binding does not exist",
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindAppArmorProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.GetAppArmorProfileReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, "test-profile"))
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bindingfakes.FakeImpl{}
			tc.prepare(mock)

			binder := newTestBinder(t, mock)
			resp := binder.Handle(t.Context(), tc.request)
			// The cases count the security context patches, the annotation of
			// the applied bindings is covered by TestHandleAppliedBindings.
			resp.Patches = slices.DeleteFunc(
				resp.Patches,
				func(op jsonpatch.JsonPatchOperation) bool {
					return strings.HasPrefix(op.Path, "/metadata/annotations")
				},
			)
			tc.assert(resp)
		})
	}
}

func TestContainersByImage(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		podSpec *corev1.PodSpec
		want    map[string][]string
	}{
		{
			name:    "NoContainers",
			podSpec: &corev1.PodSpec{},
			want:    map[string][]string{},
		},
		{
			name: "OnlyContainers",
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "web", Image: "nginx"},
					{Name: "sidecar", Image: "sidecar-image"},
				},
			},
			want: map[string][]string{
				"nginx":         {"web"},
				"sidecar-image": {"sidecar"},
			},
		},
		{
			name: "OnlyInitContainers",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "step1", Image: "busybox"},
					{Name: "step2", Image: "bash"},
				},
			},
			want: map[string][]string{
				"busybox": {"step1"},
				"bash":    {"step2"},
			},
		},
		{
			name: "ContainersAndInitContainers",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", Image: "bash"}},
				Containers:     []corev1.Container{{Name: "app", Image: "nginx"}},
			},
			want: map[string][]string{
				"bash":  {"init"},
				"nginx": {"app"},
			},
		},
		{
			name: "DuplicateImages",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", Image: "bash"}},
				Containers:     []corev1.Container{{Name: "app", Image: "bash"}},
			},
			want: map[string][]string{
				"bash": {"init", "app"},
			},
		},
		{
			name: "EquivalentReferences",
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "short", Image: "nginx"},
					{Name: "qualified", Image: "docker.io/library/nginx:latest"},
					{Name: "index", Image: "index.docker.io/nginx"},
					{Name: "other-tag", Image: "nginx:1.23.2"},
				},
			},
			want: map[string][]string{
				"nginx":        {"short", "qualified", "index"},
				"nginx:1.23.2": {"other-tag"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The containers are grouped by their normalized image.
			want := map[string][]string{}
			for image, names := range tc.want {
				want[util.NormalizeImage(image)] = names
			}

			got := map[string][]string{}

			for image, ctrs := range containersByImage(podContainers(&corev1.Pod{Spec: *tc.podSpec})) {
				for _, c := range ctrs {
					got[image] = append(got[image], c.Name)
				}
			}

			require.Equal(t, want, got)
		})
	}
}

// podChanged used to be assigned rather than accumulated across the container
// and binding loops, so a binding that mutated an earlier container was
// discarded whenever the last container evaluated already carried the bound
// context. The pod was then admitted unmutated and ran unconfined.
func TestHandleAccumulatesChangesAcrossContainers(t *testing.T) {
	t.Parallel()

	const boundType = "bound_type.process"

	mock := &bindingfakes.FakeImpl{}
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{
			{
				Spec: profilebindingapi.ProfileBindingSpec{
					ProfileRef: profilebindingapi.ProfileRef{
						Kind: profilebindingapi.ProfileBindingKindSelinuxProfile,
					},
					Image: "foo",
				},
			},
		},
	}, nil)
	mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
		Status: selinuxprofileapi.SelinuxProfileStatus{
			StatusBase: profilebaseapi.StatusBase{Status: "Installed"},
			Usage:      boundType,
		},
	}, nil)

	// Two containers of the same bound image. The second already carries the
	// bound SELinux type, the first carries none.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "pod-"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "unconstrained", Image: "foo"},
				{
					Name:  "already-bound",
					Image: "foo",
					SecurityContext: &corev1.SecurityContext{
						SELinuxOptions: &corev1.SELinuxOptions{Type: boundType},
					},
				},
			},
		},
	}

	raw, err := json.Marshal(pod)
	require.NoError(t, err)

	binder := newTestBinder(t, mock)
	resp := binder.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	})

	require.True(t, resp.Allowed)
	require.NotEmpty(t, resp.Patches,
		"the first container's binding must not be dropped because the second already matched")
}

// Wildcard bindings used to be tracked in a single variable, so only the last
// one applied, and they never overrode a value the pod or a container set
// itself. A pod could then escape a namespace wide binding by setting
// Unconfined.
func TestUpdatePodWildcardBindings(t *testing.T) {
	t.Parallel()

	const (
		wildcardSeccomp = "operator/wildcard.json"
		boundSeccomp    = "operator/bound.json"
		wildcardSelinux = "wildcard_type.process"
	)

	bindings := []profilebindingapi.ProfileBinding{
		{
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
					Name: "wildcard",
				},
				Image: profilebindingapi.SelectAllContainersImage,
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
		{
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
					Name: "bound",
				},
				Image: "bound",
			},
		},
	}

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileCalls(func(_ context.Context, key types.NamespacedName) (
		*seccompprofileapi.SeccompProfile, error,
	) {
		localhostProfile := wildcardSeccomp
		if key.Name == "bound" {
			localhostProfile = boundSeccomp
		}

		return &seccompprofileapi.SeccompProfile{
			Status: seccompprofileapi.SeccompProfileStatus{
				StatusBase: profilebaseapi.StatusBase{
					Status: secprofnodestatusapi.ProfileStateInstalled,
				},
				LocalhostProfile: localhostProfile,
			},
		}, nil
	})
	mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
		Status: selinuxprofileapi.SelinuxProfileStatus{
			StatusBase: profilebaseapi.StatusBase{
				Status: secprofnodestatusapi.ProfileStateInstalled,
			},
			Usage: wildcardSelinux,
		},
	}, nil)

	unconfined := &corev1.SecurityContext{
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
	}
	rawPod, err := json.Marshal(&corev1.Pod{
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
				SELinuxOptions: &corev1.SELinuxOptions{Type: "spc_t", Level: "s0:c1,c2"},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Image: "foo", SecurityContext: unconfined.DeepCopy()},
			},
			Containers: []corev1.Container{
				{Name: "plain", Image: "foo"},
				{Name: "unconfined", Image: "foo", SecurityContext: unconfined.DeepCopy()},
				{Name: "bound", Image: "bound", SecurityContext: unconfined.DeepCopy()},
			},
		},
	})
	require.NoError(t, err)

	binder := newTestBinder(t, mock)
	pod, _, resp := binder.updatePod(t.Context(), bindings, &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: rawPod},
		},
	})
	require.Nil(t, resp)

	seccompOf := func(profile string) *corev1.SeccompProfile {
		return &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &profile,
		}
	}

	// Both wildcard kinds apply on pod level, overriding the pod's own value.
	// The SELinux level is kept, because the cluster may require it.
	require.Equal(t, seccompOf(wildcardSeccomp), pod.Spec.SecurityContext.SeccompProfile)
	require.Equal(
		t,
		&corev1.SELinuxOptions{Type: wildcardSelinux, Level: "s0:c1,c2"},
		pod.Spec.SecurityContext.SELinuxOptions,
	)

	// Containers without an own value inherit the pod level one.
	require.Nil(t, pod.Spec.Containers[0].SecurityContext)

	// Container level values would take precedence, so they are overwritten.
	require.Equal(
		t,
		seccompOf(wildcardSeccomp),
		pod.Spec.InitContainers[0].SecurityContext.SeccompProfile,
	)
	require.Equal(
		t,
		seccompOf(wildcardSeccomp),
		pod.Spec.Containers[1].SecurityContext.SeccompProfile,
	)

	// Image specific bindings take precedence over wildcard bindings.
	require.Equal(t, seccompOf(boundSeccomp), pod.Spec.Containers[2].SecurityContext.SeccompProfile)
	require.Nil(t, pod.Spec.Containers[2].SecurityContext.SELinuxOptions)
}

// seccompBinding returns a seccomp profile binding created at the provided
// offset in seconds.
func seccompBinding(name, profile, image string, created int64) profilebindingapi.ProfileBinding {
	return profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(time.Unix(created, 0)),
		},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: profile,
			},
			Image: image,
		},
	}
}

// localhostSeccompProfiles returns the profiles with the localhost profile set
// to the profile name.
func localhostSeccompProfiles(_ context.Context, key types.NamespacedName) (
	*seccompprofileapi.SeccompProfile, error,
) {
	return &seccompprofileapi.SeccompProfile{
		Status: seccompprofileapi.SeccompProfileStatus{
			StatusBase: profilebaseapi.StatusBase{
				Status: secprofnodestatusapi.ProfileStateInstalled,
			},
			LocalhostProfile: key.Name,
		},
	}, nil
}

// Conflicting bindings used to be applied in the random order of the informer
// list, so the last one won. The oldest binding has to win deterministically,
// and the others have to be reported.
func TestUpdatePodConflictingBindings(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		bindings []profilebindingapi.ProfileBinding
		want     string
		wantPod  bool
		warnings int
	}{
		{
			name: "image bindings, oldest first",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("old", "old-profile", "foo", 1),
				seccompBinding("new", "new-profile", "foo", 2),
			},
			want:     "old-profile",
			warnings: 1,
		},
		{
			name: "image bindings, newest first",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("new", "new-profile", "foo", 2),
				seccompBinding("old", "old-profile", "foo", 1),
			},
			want:     "old-profile",
			warnings: 1,
		},
		{
			name: "image bindings created at the same time are ordered by name",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("b", "b-profile", "foo", 1),
				seccompBinding("a", "a-profile", "foo", 1),
			},
			want:     "a-profile",
			warnings: 1,
		},
		{
			name: "wildcard bindings, newest first",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("new", "new-profile", profilebindingapi.SelectAllContainersImage, 2),
				seccompBinding("old", "old-profile", profilebindingapi.SelectAllContainersImage, 1),
			},
			want:     "old-profile",
			wantPod:  true,
			warnings: 1,
		},
		{
			name: "bindings of the same profile do not conflict",
			bindings: []profilebindingapi.ProfileBinding{
				seccompBinding("new", "profile", "foo", 2),
				seccompBinding("old", "profile", "foo", 1),
			},
			want: "profile",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bindingfakes.FakeImpl{}
			mock.GetSeccompProfileCalls(localhostSeccompProfiles)

			recorder := events.NewFakeRecorder(10)
			binder := newTestBinder(t, mock)
			binder.record = utils.NewSafeRecorder(recorder)

			pod, warnings, resp := binder.updatePod(t.Context(), tc.bindings, &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawObject(t, testPod),
				},
			})
			require.Nil(t, resp)
			require.Len(t, warnings, tc.warnings)
			require.Len(t, recorder.Events, tc.warnings)

			if tc.wantPod {
				require.Equal(
					t, tc.want, *pod.Spec.SecurityContext.SeccompProfile.LocalhostProfile,
				)

				return
			}

			require.Nil(t, pod.Spec.SecurityContext)
			require.Equal(
				t, tc.want, *pod.Spec.Containers[0].SecurityContext.SeccompProfile.LocalhostProfile,
			)
		})
	}
}

// The binding webhook marks the pods with the bindings it applied, so that
// the binding tracker only tracks pods which use a binding. A value set by the
// pod author must not survive.
func TestHandleAppliedBindings(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileCalls(localhostSeccompProfiles)
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{
			seccompBinding("image", "image-profile", "foo", 1),
			seccompBinding("other-image", "image-profile", "bar", 1),
			seccompBinding(
				"wildcard", "wildcard-profile", profilebindingapi.SelectAllContainersImage, 1,
			),
		},
	}, nil)

	pod := testPod.DeepCopy()
	pod.Annotations = map[string]string{
		profilebindingapi.AppliedBindingsAnnotation: "spoofed",
	}

	resp := newTestBinder(t, mock).Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    rawObject(t, pod),
		},
	})
	require.True(t, resp.Allowed)
	require.Contains(t, resp.Patches, jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      "/metadata/annotations/spo.x-k8s.io~1profile-bindings",
		Value:     "image,wildcard",
	})

	// Without an applied binding, a spoofed value gets removed.
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{}, nil)

	resp = newTestBinder(t, mock).Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    rawObject(t, pod),
		},
	})
	require.True(t, resp.Allowed)
	require.Equal(t, []jsonpatch.JsonPatchOperation{{
		Operation: "remove",
		Path:      "/metadata/annotations/spo.x-k8s.io~1profile-bindings",
	}}, resp.Patches)
}

// Bindings used to compare the images as strings, so a pod could escape a
// binding by writing the same image differently.
func TestHandleNormalizesImages(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileCalls(localhostSeccompProfiles)
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{
			seccompBinding("binding", "profile", "nginx:1.23.2", 1),
		},
	}, nil)

	for _, image := range []string{
		"nginx:1.23.2", "docker.io/nginx:1.23.2", "docker.io/library/nginx:1.23.2",
	} {
		pod := testPod.DeepCopy()
		pod.Spec.Containers[0].Image = image

		resp := newTestBinder(t, mock).Handle(t.Context(), admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    rawObject(t, pod),
			},
		})
		require.True(t, resp.Allowed, image)
		require.Contains(t, resp.Patches, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/spec/containers/0/securityContext",
			Value: map[string]any{
				"seccompProfile": map[string]any{
					"type":             "Localhost",
					"localhostProfile": "profile",
				},
			},
		}, image)
	}
}

// Recorded profiles are named after the recording and container only, so a
// recording in another namespace can produce the profile a binding expects.
func TestHandleWarnsAboutProfilesRecordedElsewhere(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileCalls(func(ctx context.Context, key types.NamespacedName) (
		*seccompprofileapi.SeccompProfile, error,
	) {
		profile, err := localhostSeccompProfiles(ctx, key)
		profile.Labels = map[string]string{
			profilerecordingapi.ProfileToRecordingNamespaceLabel: strings.TrimSuffix(
				key.Name,
				"-profile",
			),
		}

		return profile, err
	})
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{
			seccompBinding("same", "pod-ns-profile", "foo", 1),
			seccompBinding("other", "other-ns-profile", "bar", 1),
			seccompBinding(
				"applied",
				"other-ns-profile",
				profilebindingapi.SelectAllContainersImage,
				1,
			),
		},
	}, nil)

	recorder := events.NewFakeRecorder(10)
	binder := newTestBinder(t, mock)
	binder.record = utils.NewSafeRecorder(recorder)

	resp := binder.Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Namespace: "pod-ns",
			Object:    rawObject(t, testPod),
		},
	})
	require.True(t, resp.Allowed)

	// Only the applied binding to the profile of another namespace warns.
	require.Len(t, resp.Warnings, 1)
	require.Contains(t, resp.Warnings[0], "profile binding applied")
	require.Contains(t, resp.Warnings[0], "recorded in namespace other-ns")
	require.Len(t, recorder.Events, 1)
	require.Contains(t, <-recorder.Events, reasonRecordedElsewhere)
}

// Dry-run requests must not have side effects like events.
func TestHandleDryRunRecordsNoEvents(t *testing.T) {
	t.Parallel()

	mock := &bindingfakes.FakeImpl{}
	mock.GetSeccompProfileCalls(localhostSeccompProfiles)
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{
			seccompBinding("old", "old-profile", "foo", 1),
			seccompBinding("new", "new-profile", "foo", 2),
		},
	}, nil)

	for _, dryRun := range []bool{true, false} {
		recorder := events.NewFakeRecorder(10)
		binder := newTestBinder(t, mock)
		binder.record = utils.NewSafeRecorder(recorder)

		resp := binder.Handle(t.Context(), admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    rawObject(t, testPod),
				DryRun:    new(dryRun),
			},
		})
		require.True(t, resp.Allowed)
		require.Len(t, resp.Warnings, 1, "the client gets warned in both cases")

		if dryRun {
			require.Empty(t, recorder.Events)
		} else {
			require.Len(t, recorder.Events, 1)
		}
	}
}

// A binding with an invalid podSelector is skipped and reported, like a
// recording with one.
func TestPodMatchesSelectorReportsInvalidSelector(t *testing.T) {
	t.Parallel()

	recorder := events.NewFakeRecorder(1)
	binder := newTestBinder(t, &bindingfakes.FakeImpl{})
	binder.record = utils.NewSafeRecorder(recorder)

	pb := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding"},
		Spec: profilebindingapi.ProfileBindingSpec{
			PodSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "app", Operator: metav1.LabelSelectorOpIn,
			}}},
		},
	}

	require.False(t, binder.podMatchesSelector(testPod, pb))
	require.Len(t, recorder.Events, 1)
	require.Contains(t, <-recorder.Events, reasonInvalidPodSelector)
}
