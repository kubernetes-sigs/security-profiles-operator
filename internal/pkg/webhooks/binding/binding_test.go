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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
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
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{}, nil)
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
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{}, nil)
				mock.DecodePodReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		{ // success pod changed
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
							Status: secprofnodestatusv1alpha1.ProfileStateInstalled,
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
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{ // success pod changed with * image
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
								},
								Image: v1alpha1.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
							Status: secprofnodestatusv1alpha1.ProfileStateInstalled,
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
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{ // selinux success pod changed
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSelinuxProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
					Status: selinuxprofileapi.SelinuxProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
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
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{ // selinux success pod changed with * image
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSelinuxProfile,
								},
								Image: v1alpha1.SelectAllContainersImage,
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSelinuxProfileReturns(&selinuxprofileapi.SelinuxProfile{
					Status: selinuxprofileapi.SelinuxProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
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
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{ // success unsupported kind
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: "unsupported",
								},
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
							Status: secprofnodestatusv1alpha1.ProfileStateInstalled,
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
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{ // failure get seccomp profile malicious
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
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
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
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
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
							Status: secprofnodestatusv1alpha1.ProfileStateInstalled,
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
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
								},
								Image: "foo",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.GetSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
					Status: seccompprofileapi.SeccompProfileStatus{
						StatusBase: profilebasev1alpha1.StatusBase{
							Status: secprofnodestatusv1alpha1.ProfileStateInstalled,
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
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
								},
							},
							Status: v1alpha1.ProfileBindingStatus{
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
				require.True(t, resp.AdmissionResponse.Allowed)
			},
		},
		{ // failure delete on remove pod from binding at  UpdateResourceStatus
			prepare: func(mock *bindingfakes.FakeImpl) {
				mock.ListProfileBindingsReturns(&v1alpha1.ProfileBindingList{
					Items: []v1alpha1.ProfileBinding{
						{
							Spec: v1alpha1.ProfileBindingSpec{
								ProfileRef: v1alpha1.ProfileRef{
									Kind: v1alpha1.ProfileBindingKindSeccompProfile,
								},
							},
							Status: v1alpha1.ProfileBindingStatus{
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
	} {
		mock := &bindingfakes.FakeImpl{}
		tc.prepare(mock)

		binder := podBinder{impl: mock, log: logr.Discard()}
		resp := binder.Handle(context.Background(), tc.request)
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
			result.Range(func(k, v interface{}) bool {
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
