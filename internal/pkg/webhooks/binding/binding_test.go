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
	"k8s.io/apimachinery/pkg/types"
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
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, "pod unchanged", resp.Result.Message)
			},
		},
		{ // success pod update skips mutation
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
		{ // error could not list profile bindings
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
		{ // error failed to decode pod
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{}, nil)
				mock.DecodePodReturns(nil, errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
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
	mock.DecodePodReturns(pod.DeepCopy(), nil)

	raw, err := json.Marshal(pod)
	require.NoError(t, err)

	binder := podBinder{impl: mock, log: logr.Discard()}
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
	mock.DecodePodReturns(&corev1.Pod{
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
	}, nil)

	binder := podBinder{impl: mock, log: logr.Discard()}
	pod, resp := binder.updatePod(t.Context(), bindings, &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create},
	})
	require.Equal(t, admission.Response{}, resp)

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
