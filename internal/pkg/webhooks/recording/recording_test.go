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
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
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

// annotatedPod returns the test pod with the logs recording annotation of
// its container set to value.
func annotatedPod(value string) *corev1.Pod {
	pod := testPod.DeepCopy()
	pod.Annotations = map[string]string{"io.containers.trace-logs/container": value}

	return pod
}

// windowsPod returns the test pod declared as Windows pod.
func windowsPod() *corev1.Pod {
	pod := testPod.DeepCopy()
	pod.Spec.OS = &corev1.PodOS{Name: corev1.Windows}

	return pod
}

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
			// A recording created after the pod must not start on it: the
			// security context is immutable and the recorder daemons
			// would miss the container start.
			name: "success pod update without the recording annotation stays unchanged",
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
					OldObject: rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
				require.Equal(t, "pod unchanged", resp.Result.Message)
			},
		},
		{
			name: "success pod update re-applies the removed recording annotation",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							ObjectMeta: metav1.ObjectMeta{Name: "rec"},
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
					OldObject: rawPod(t, annotatedPod("rec_container_abcde_1661693966")),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)
				require.Equal(t, "add", resp.Patches[0].Operation)
				require.Equal(t, "/metadata/annotations", resp.Patches[0].Path)
				require.Equal(t,
					map[string]any{"io.containers.trace-logs/container": "rec_container_abcde_1661693966"},
					resp.Patches[0].Value,
				)
			},
		},
		{
			name: "error failed to decode old pod",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					Object:    rawPod(t, testPod),
					OldObject: runtime.RawExtension{Raw: []byte("{")},
				},
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
		{
			name: "success windows pod is skipped",
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
					Operation: admissionv1.Create,
					Object:    rawPod(t, windowsPod()),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
				require.Equal(t, "windows pod, skipping mutation", resp.Result.Message)
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
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod),
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
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Empty(t, resp.Patches)
			},
		},
		{
			// An invalid selector of one recording used to reject every pod in
			// the namespace. The recording is skipped instead, and the others
			// still apply.
			name: "success invalid pod selector skips the recording",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
					Items: []profilerecordingapi.ProfileRecording{
						{
							ObjectMeta: metav1.ObjectMeta{Name: "invalid"},
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
						{
							ObjectMeta: metav1.ObjectMeta{Name: "valid"},
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
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod),
				},
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Len(t, resp.Patches, 1)

				annotations, ok := resp.Patches[0].Value.(map[string]any)
				require.True(t, ok)

				value, ok := annotations["io.containers.trace-bpf/container"].(string)
				require.True(t, ok)
				require.True(t, strings.HasPrefix(value, "valid_container_"))
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
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod),
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
// collection. Values of the recording itself have to be kept, on update the
// value the old pod carried.
func TestHandleKeepsRecordingAnnotation(t *testing.T) {
	t.Parallel()

	const valid = "rec_container_abcde_1661693966"

	for _, tc := range []struct {
		name      string
		operation admissionv1.Operation
		old       string
		existing  string
		// keep expects the existing value to stay, want the exact new
		// value, otherwise a fresh value is expected.
		keep bool
		want string
	}{
		{name: "own recording on create", operation: admissionv1.Create, existing: valid, keep: true},
		{name: "other recording on create", operation: admissionv1.Create, existing: "other_container_abcde_1661693966"},
		{name: "other container on create", operation: admissionv1.Create, existing: "rec_other_abcde_1661693966"},
		{name: "recording prefix on create", operation: admissionv1.Create, existing: "rec_container_injected"},
		{name: "additional parts on create", operation: admissionv1.Create, existing: "rec_container_abcde_1661693966_x"},
		{name: "empty on create", operation: admissionv1.Create, existing: ""},
		{name: "own recording on update", operation: admissionv1.Update, old: valid, existing: valid, keep: true},
		{
			name:      "other recording on update",
			operation: admissionv1.Update,
			old:       "other_container_abcde_1661693966",
			existing:  "other_container_abcde_1661693966",
		},
		{
			name:      "changed nonce on update",
			operation: admissionv1.Update,
			old:       valid,
			existing:  "rec_container_fghij_1661693999",
			want:      valid,
		},
		{
			name:      "spoofed on update",
			operation: admissionv1.Update,
			old:       valid,
			existing:  "other_container_abcde_1661693966",
			want:      valid,
		},
		{name: "empty on update", operation: admissionv1.Update, old: "", existing: ""},
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

			request := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: tc.operation,
					Object:    rawPod(t, annotatedPod(tc.existing)),
				},
			}
			if tc.operation == admissionv1.Update {
				request.OldObject = rawPod(t, annotatedPod(tc.old))
			}

			resp := newTestRecorder(t, mock).Handle(t.Context(), request)
			require.True(t, resp.Allowed)

			if tc.keep {
				require.Empty(t, resp.Patches)

				return
			}

			// The security context patch comes with the creation, in no
			// particular order.
			patches := resp.Patches
			if tc.operation == admissionv1.Create {
				require.Len(t, patches, 2)
				patches = slices.DeleteFunc(patches, func(patch jsonpatch.Operation) bool {
					return !strings.HasPrefix(patch.Path, "/metadata/annotations")
				})
			}

			require.Len(t, patches, 1)
			value, ok := patches[0].Value.(string)
			require.True(t, ok)

			if tc.want != "" {
				require.Equal(t, tc.want, value)

				return
			}

			require.True(t, strings.HasPrefix(value, "rec_container_"), value)
		})
	}
}

// TestHandleConflictingRecordings asserts that the oldest of two recordings of
// the same container records it, in whatever order the cache lists them.
func TestHandleConflictingRecordings(t *testing.T) {
	t.Parallel()

	recording := func(name string, created int64) profilerecordingapi.ProfileRecording {
		return profilerecordingapi.ProfileRecording{
			ObjectMeta: metav1.ObjectMeta{
				Name:              name,
				Namespace:         "ns",
				CreationTimestamp: metav1.Unix(created, 0),
			},
			Spec: profilerecordingapi.ProfileRecordingSpec{
				Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
				Recorder:    profilerecordingapi.ProfileRecorderLogs,
				PodSelector: selectAll,
			},
		}
	}

	for _, order := range [][]profilerecordingapi.ProfileRecording{
		{recording("older", 1), recording("newer", 2)},
		{recording("newer", 2), recording("older", 1)},
	} {
		mock := &recordingfakes.FakeImpl{}
		mock.ListProfileRecordingsReturns(
			&profilerecordingapi.ProfileRecordingList{Items: order}, nil,
		)

		sut := newTestRecorder(t, mock)
		recorder := events.NewFakeRecorder(10)
		sut.record = utils.NewSafeRecorder(recorder)

		resp := sut.Handle(t.Context(), admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    rawPod(t, testPod.DeepCopy()),
			},
		})
		require.True(t, resp.Allowed)

		annotations := slices.DeleteFunc(resp.Patches, func(patch jsonpatch.Operation) bool {
			return !strings.HasPrefix(patch.Path, "/metadata/annotations")
		})
		require.Len(t, annotations, 1)

		value, err := json.Marshal(annotations[0].Value)
		require.NoError(t, err)
		require.Contains(t, string(value), "older_container_")

		require.Len(t, recorder.Events, 1)
		require.Contains(t, <-recorder.Events, reasonConflictingRecording)
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

// Dry-run requests must not have side effects like events.
func TestHandleDryRunRecordsNoEvents(t *testing.T) {
	t.Parallel()

	mock := &recordingfakes.FakeImpl{}
	mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
		Items: []profilerecordingapi.ProfileRecording{{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid"},
			Spec: profilerecordingapi.ProfileRecordingSpec{
				Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
				Recorder: profilerecordingapi.ProfileRecorderBpf,
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
					}},
				},
			},
		}},
	}, nil)

	for _, dryRun := range []bool{true, false} {
		recorder := events.NewFakeRecorder(10)
		podRecorder := newTestRecorder(t, mock)
		podRecorder.record = utils.NewSafeRecorder(recorder)

		resp := podRecorder.Handle(t.Context(), admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    rawPod(t, testPod),
				DryRun:    new(dryRun),
			},
		})
		require.True(t, resp.Allowed)

		if dryRun {
			require.Empty(t, recorder.Events)
		} else {
			require.Len(t, recorder.Events, 1)
			require.Contains(t, <-recorder.Events, "InvalidPodSelector")
		}
	}
}
