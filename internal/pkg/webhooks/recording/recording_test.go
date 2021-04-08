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

package recording

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording/recordingfakes"
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
					Name: "container",
				},
			},
		},
	}
)

func TestHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*recordingfakes.FakeImpl)
		request admission.Request
		assert  func(admission.Response)
	}{
		{ // success pod unchanged
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{}, nil)
				mock.DecodePodReturns(&corev1.Pod{}, nil)
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, metav1.StatusReason("pod unchanged"), resp.Result.Reason)
			},
		},
		{ // error could not list profile recordings
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{ // error failed to decode pod
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{}, nil)
				mock.DecodePodReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		{ // success pod changed
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "SeccompProfile",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.Nil(t, err)
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
		{ // success no seccomp profile
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "OtherProfile",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{ // failure LabelSelectorAsSelector
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "SeccompProfile",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{ // failure UpdateResource
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "SeccompProfile",
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
				mock.UpdateResourceReturns(errTest)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.Nil(t, err)
							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{ // success pod already tracked
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "SeccompProfile",
							},
						},
					},
				}, nil)
				pod := testPod.DeepCopy()
				pod.Annotations = map[string]string{
					"io.containers.trace-syscall/container": "of:/some/path.json",
				}
				mock.DecodePodReturns(pod, nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: func() []byte {
							b, err := json.Marshal(testPod.DeepCopy())
							require.Nil(t, err)
							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.AdmissionResponse.Allowed)
				require.Len(t, resp.Patches, 0)
			},
		},
		{ // success pod deleted
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "SeccompProfile",
							},
							Status: v1alpha1.ProfileRecordingStatus{
								ActiveWorkloads: []string{"1", "2", "3"},
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
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
		{ // failure pod deleted on UpdateResource
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{
					Items: []v1alpha1.ProfileRecording{
						{
							Spec: v1alpha1.ProfileRecordingSpec{
								Kind: "SeccompProfile",
							},
							Status: v1alpha1.ProfileRecordingStatus{
								ActiveWorkloads: []string{"1", "2", "3"},
							},
						},
					},
				}, nil)
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
				mock.UpdateResourceReturns(errTest)
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
		mock := &recordingfakes.FakeImpl{}
		tc.prepare(mock)

		recorder := podSeccompRecorder{impl: mock, log: logr.Discard()}
		resp := recorder.Handle(context.Background(), tc.request)
		tc.assert(resp)
	}
}
