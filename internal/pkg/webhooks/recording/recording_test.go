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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// selectAll matches every pod, unlike a nil selector.
	selectAll = &metav1.LabelSelector{}
)

func rawPod(t *testing.T, pod *corev1.Pod) runtime.RawExtension {
	t.Helper()

	b, err := json.Marshal(pod)
	require.NoError(t, err)

	return runtime.RawExtension{Raw: b}
}

func newTestRecorder(t *testing.T, mock *recordingfakes.FakeImpl) *podSeccompRecorder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	return &podSeccompRecorder{
		impl:    mock,
		decoder: admission.NewDecoder(scheme),
		log:     logr.Discard(),
		record:  utils.NewSafeRecorder(nil),
	}
}

func TestHandle(t *testing.T) {
	t.Parallel()

	trackedPod := testPod.DeepCopy()
	trackedPod.Annotations = map[string]string{
		"io.containers.trace-logs/container": "my-little-profile-recording-container-0-1661693966",
	}
	localhostProfile := "operator/log-enricher-trace.json"
	trackedPod.Spec.SecurityContext = &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &localhostProfile,
		},
	}

	for _, tc := range []struct {
		name    string
		prepare func(*recordingfakes.FakeImpl)
		request admission.Request
		assert  func(admission.Response)
	}{
		{
			name: "success pod unchanged",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: rawPod(t, &corev1.Pod{}),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, "pod unchanged", resp.Result.Message)
			},
		},
		{
			name: "error could not list profile recordings",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{
			name: "error failed to decode pod",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{Raw: []byte("{")},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		{
			name: "success pod changed - tailing logs",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:        profilerecordingapi.ProfileRecordingKindSelinuxProfile,
								Recorder:    profilerecordingapi.ProfileRecorderLogs,
								PodSelector: selectAll,
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 2) // 2 because security context and the annotation
			},
		},
		{
			name: "success pod update only tracks, security context is immutable",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
								Recorder:    profilerecordingapi.ProfileRecorderLogs,
								PodSelector: selectAll,
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					Object:    rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
				require.Equal(t, "add", resp.Patches[0].Operation)
				require.Equal(t, "/metadata/annotations", resp.Patches[0].Path)
			},
		},
		{
			name: "success pod changed",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
								Recorder:    profilerecordingapi.ProfileRecorderBpf,
								PodSelector: selectAll,
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
			},
		},
		{
			name: "success no seccomp profile",
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
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{
			name: "failure invalid pod selector",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
								Recorder: profilerecordingapi.ProfileRecorderBpf,
								PodSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{{
										Key:      "app",
										Operator: "Invalid",
									}},
								},
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		{
			name: "success pod already tracked",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "my-little-profile-recording",
								Namespace: "test-ns",
							},
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
								Recorder:    profilerecordingapi.ProfileRecorderLogs,
								PodSelector: selectAll,
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, trackedPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				// 2 because the container security context and the annotation,
				// which does not have the expected format.
				require.Len(t, resp.Patches, 2)
			},
		},
		{
			name: "success apparmor profile recording should be admitted",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							Spec: profilerecordingapi.ProfileRecordingSpec{
								Kind:        profilerecordingapi.ProfileRecordingKindAppArmorProfile,
								Recorder:    profilerecordingapi.ProfileRecorderBpf,
								PodSelector: selectAll,
							},
						},
					},
				}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &recordingfakes.FakeImpl{}
			tc.prepare(mock)

			resp := newTestRecorder(t, mock).Handle(t.Context(), tc.request)
			tc.assert(resp)
		})
	}
}

// The annotation value carries a random nonce and a timestamp, so it differs
// on every admission. It used to be rewritten on every pod update, which
// renamed the recorded profile between the recording start and its
// collection. Values of the recording itself have to be kept.
func TestHandleKeepsRecordingAnnotation(t *testing.T) {
	t.Parallel()

	const key = "io.containers.trace-logs/container"

	for _, tc := range []struct {
		name     string
		existing string
		keep     bool
	}{
		{name: "own recording", existing: "rec_container_abcde_1661693966", keep: true},
		{name: "other recording", existing: "other_container_abcde_1661693966"},
		{name: "other container", existing: "rec_other_abcde_1661693966"},
		{name: "recording prefix", existing: "rec_container_injected"},
		{name: "additional parts", existing: "rec_container_abcde_1661693966_x"},
		{name: "empty", existing: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &recordingfakes.FakeImpl{}
			mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
				Items: []profilerecordingapi.ProfileRecording{{
					ObjectMeta: metav1.ObjectMeta{Name: "rec", Namespace: "ns"},
					Spec: profilerecordingapi.ProfileRecordingSpec{
						Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
						Recorder:    profilerecordingapi.ProfileRecorderLogs,
						PodSelector: selectAll,
					},
				}},
			}, nil)

			pod := testPod.DeepCopy()
			pod.Annotations = map[string]string{key: tc.existing}

			resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					Object:    rawPod(t, pod),
				},
			})

			require.True(t, resp.Allowed)

			if tc.keep {
				require.Empty(t, resp.Patches)

				return
			}

			require.Len(t, resp.Patches, 1)
			value, ok := resp.Patches[0].Value.(string)
			require.True(t, ok)
			require.True(t, strings.HasPrefix(value, "rec_container_"), value)
		})
	}
}

func TestUpdateSeccompSecurityContext(t *testing.T) {
	t.Parallel()

	ctr := &corev1.Container{Name: "container"}
	(&podSeccompRecorder{}).updateSeccompSecurityContext(
		ctr, &profilerecordingapi.ProfileRecording{},
	)

	// Seccomp profiles are cluster scoped, so the path must not contain a
	// namespace directory, otherwise the kubelet cannot find the profile.
	require.Equal(t, corev1.SeccompProfileTypeLocalhost, ctr.SecurityContext.SeccompProfile.Type)
	require.Equal(
		t, "operator/log-enricher-trace.json",
		*ctr.SecurityContext.SeccompProfile.LocalhostProfile,
	)
}
