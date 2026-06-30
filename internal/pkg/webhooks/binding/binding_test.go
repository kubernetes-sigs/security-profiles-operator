/*
Copyright 2021 The Kubernetes Authors.

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
	"encoding/json"
	"errors"
	"net/http"
	"sync"
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
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding/bindingfakes"
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

func TestHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*bindingfakes.FakeImpl)
		request admission.Request
		assert  func(admission.Response)
	}{
		{ // success pod unchanged
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{}, nil)
				mock.DecodePodReturns(&corev1.Pod{}, nil)
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, "pod unchanged", resp.Result.Message)
			},
		},
		{ // error could not list profile bindings
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{ // error failed to decode pod
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{}, nil)
				mock.DecodePodReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		//nolint:dupl // test duplicates are fine
		{ // success pod changed
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // success pod changed when podSelector matches
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
				mock.DecodePodReturns(testPodWithLabels.DeepCopy(), nil)
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
		{ // success pod unchanged when podSelector does not match
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
				mock.DecodePodReturns(testPodWithLabels.DeepCopy(), nil)
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
		{ // success pod changed with * image
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // success seccomp pod security context overwrite with * image
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
				require.Len(t, resp.Patches, 2) // add localProfile, replace type with Localhost
			},
		},
		{ // selinux success pod changed
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // success selinux pod security context overwrite with * image
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // selinux success pod changed with * image
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // apparmor success pod changed
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // success apparmor security context overwritten with * image
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
				require.Len(t, resp.Patches, 2)
			},
		},
		//nolint:dupl // test duplicates are fine
		{ // apparmor success pod changed with * image
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		{ // failure get apparmor profile errored
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetAppArmorProfileReturns(nil, errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		//nolint:dupl // test duplicates are fine
		{ // failure get apparmor profile without status
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetAppArmorProfileReturns(&apparmorprofileapi.AppArmorProfile{
					Status: apparmorprofileapi.AppArmorProfileStatus{},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		{ // success unsupported kind
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
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
		//nolint:dupl // test duplicates are fine
		{ // failure get seccomp profile malicious
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		{ // failure get seccomp profile errored
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(nil, errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		//nolint:dupl // test duplicates are fine
		{ // failure on UpdateResource
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
				mock.UpdateResourceReturns(errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		//nolint:dupl // test duplicates are fine
		{ // failure on UpdateResourceStatus
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebaseapi.StatusBase{
							Status: secprofnodestatusapi.ProfileStateInstalled,
						},
					},
				}, nil)
				mock.UpdateResourceStatusReturns(errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		{ // success pod deleted
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
							},
							Status: profilebindingapi.ProfileBindingStatus{
								ActiveWorkloads: []string{"1", "2", "3"},
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
			},
		},
		{ // failure delete on remove pod from binding at  UpdateResourceStatus
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
					Items: []profilebindingapi.ProfileBinding{
						{
							Spec: profilebindingapi.ProfileBindingSpec{
								ProfileRef: profilebindingapi.ProfileRef{
									Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
								},
							},
							Status: profilebindingapi.ProfileBindingStatus{
								ActiveWorkloads: []string{"1", "2", "3"},
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.UpdateResourceStatusReturns(errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Delete,
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{ // success when the profile referenced in the profile binding doesn't exist.
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
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetAppArmorProfileReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, "test-profile"))
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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
		mock := &bindingfakes.FakeImpl{}
		tc.prepare(mock)

		binder := podBinder{impl: mock, log: logr.Discard()}
		resp := binder.Handle(t.Context(), tc.request)
		tc.assert(resp)
	}
}

func TestNewContainerMap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		podSpec *corev1.PodSpec
		want    map[string]containerList
	}{
		{
			name:    "NoContainers",
			podSpec: &corev1.PodSpec{},
			want:    map[string]containerList{},
		},
		{
			name: "OnlyContainers",
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "web",
						Image: "nginx",
					},
					{
						Name:  "sidecar",
						Image: "sidecar-image",
					},
				},
			},
			want: map[string]containerList{
				"nginx": {
					{
						Name:  "web",
						Image: "nginx",
					},
				},
				"sidecar-image": {
					{
						Name:  "sidecar",
						Image: "sidecar-image",
					},
				},
			},
		},
		{
			name: "OnlyInitContainers",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{
					{
						Name:  "step1",
						Image: "busybox",
					},
					{
						Name:  "step2",
						Image: "bash",
					},
				},
			},
			want: map[string]containerList{
				"busybox": {
					{
						Name:  "step1",
						Image: "busybox",
					},
				},
				"bash": {
					{
						Name:  "step2",
						Image: "bash",
					},
				},
			},
		},
		{
			name: "ContainersAndInitContainers",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name:  "init",
					Image: "bash",
				}},
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "nginx",
				}},
			},
			want: map[string]containerList{
				"bash": {
					{
						Name:  "init",
						Image: "bash",
					},
				},
				"nginx": {
					{
						Name:  "app",
						Image: "nginx",
					},
				},
			},
		},
		{
			name: "DuplicateImages",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name:  "init",
					Image: "bash",
				}},
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "bash",
				}},
			},
			want: map[string]containerList{
				"bash": {
					{
						Name:  "app",
						Image: "bash",
					},
					{
						Name:  "init",
						Image: "bash",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var result sync.Map

			initContainerMap(&result, tc.podSpec)
			result.Range(func(k, v any) bool {
				ks, ok := k.(string)
				require.True(t, ok)

				vl, ok := v.(containerList)
				require.True(t, ok)

				require.Equal(t, tc.want[ks], vl)

				return true
			})
		})
	}
}
