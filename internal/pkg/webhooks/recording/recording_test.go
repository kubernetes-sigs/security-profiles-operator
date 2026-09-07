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

package recording

import (
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

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording/recordingfakes"
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
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{}, nil)
				mock.DecodePodReturns(&corev1.Pod{}, nil)
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, "pod unchanged", resp.Result.Message)
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
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{}, nil)
				mock.DecodePodReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		// todo: bad combination, selinux + hook
		// todo: actually look at the content of the patches
		{ // success pod changed - tailing logs
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:     profilerecordingapi.ProfileRecordingKindSelinuxProfile,
								Recorder: profilerecordingapi.ProfileRecorderLogs,
							},
						},
					},
				}, nil)

				mock.GetOperatorNamespaceReturns("test-ns")
				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
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
				require.Len(t, resp.Patches, 2) // 2 because security context and the annotation
			},
		},
		{ // success pod changed
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
								Recorder: profilerecordingapi.ProfileRecorderBpf,
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
		{ // success no seccomp profile
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind: "OtherProfile",
							},
						},
					},
				}, nil)

				mock.DecodePodReturns(testPod.DeepCopy(), nil)
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{ // failure LabelSelectorAsSelector
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind: profilerecordingapi.ProfileRecordingKindSeccompProfile,
							},
						},
					},
				}, nil)

				mock.DecodePodReturns(testPod.DeepCopy(), nil)
				mock.LabelSelectorAsSelectorReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		{ // success pod already tracked
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "my-little-profile-recording",
								Namespace: "test-ns",
							},
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
								Recorder: profilerecordingapi.ProfileRecorderLogs,
							},
						},
					},
				}, nil)

				pod := testPod.DeepCopy()
				pod.Annotations = map[string]string{
					"io.containers.trace-logs/container": "my-little-profile-recording-container-0-1661693966",
				}
				localhostProfile := "operator//log-enricher-trace.json"
				pod.Spec.SecurityContext = &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type:             corev1.SeccompProfileTypeLocalhost,
						LocalhostProfile: &localhostProfile,
					},
				}
				mock.DecodePodReturns(pod, nil)
				mock.LabelSelectorAsSelectorReturns(labels.Everything(), nil)
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
				require.Len(t, resp.Patches, 3) // 3 because pod + container security context and the annotation
			},
		},
		{ // success apparmor profile recording should be admitted
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:     profilerecordingapi.ProfileRecordingKindAppArmorProfile,
								Recorder: profilerecordingapi.ProfileRecorderBpf,
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
							require.NoError(t, err)

							return b
						}(),
					},
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
			},
		},
	} {
		mock := &recordingfakes.FakeImpl{}
		tc.prepare(mock)

		recorder := podSeccompRecorder{
			impl:   mock,
			log:    logr.Discard(),
			record: utils.NewSafeRecorder(nil),
		}
		resp := recorder.Handle(t.Context(), tc.request)
		tc.assert(resp)
	}
}
