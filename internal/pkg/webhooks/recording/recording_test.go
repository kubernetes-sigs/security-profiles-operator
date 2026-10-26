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
	"path"
	"slices"
	"strings"
	"testing"

	jsonpatchapply "github.com/evanphx/json-patch/v5"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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

// patchedPod returns the pod with the patches applied.
func patchedPod(t *testing.T, pod *corev1.Pod, patches []jsonpatch.Operation) *corev1.Pod {
	t.Helper()

	patchJSON, err := json.Marshal(patches)
	require.NoError(t, err)

	patch, err := jsonpatchapply.DecodePatch(patchJSON)
	require.NoError(t, err)

	patched, err := patch.Apply(rawPod(t, pod).Raw)
	require.NoError(t, err)

	res := &corev1.Pod{}
	require.NoError(t, json.Unmarshal(patched, res))

	return res
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
		assert  func(*testing.T, admission.Response)
	}{
		{
			name: "success pod unchanged",
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{}, nil)
			},
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, &corev1.Pod{}),
				},
			},
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			request: admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod),
				},
			},
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

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
							ObjectMeta: metav1.ObjectMeta{Name: "rec"},
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
			assert: func(t *testing.T, resp admission.Response) {
				t.Helper()

				require.True(t, resp.Allowed)
				// The bpf recorder only adds the annotation, it does not
				// change the security context.
				require.Len(t, resp.Patches, 1)
				require.Equal(t, "/metadata/annotations", resp.Patches[0].Path)

				annotations, ok := resp.Patches[0].Value.(map[string]any)
				require.True(t, ok)

				value, ok := annotations["io.containers.trace-bpf-apparmor/container"].(string)
				require.True(t, ok)
				require.True(t, strings.HasPrefix(value, "rec_container_"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &recordingfakes.FakeImpl{}
			tc.prepare(mock)

			resp := newTestRecorder(t, mock).Handle(t.Context(), tc.request)
			tc.assert(t, resp)
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
		// value, removed the annotation to be removed, otherwise a fresh
		// value is expected. unannotated leaves the old pod without the
		// annotation on update.
		keep        bool
		want        string
		removed     bool
		unannotated bool
	}{
		{name: "own recording on create", operation: admissionv1.Create, existing: valid, keep: true},
		{name: "other recording on create", operation: admissionv1.Create, existing: "other_container_abcde_1661693966"},
		{name: "other container on create", operation: admissionv1.Create, existing: "rec_other_abcde_1661693966"},
		{name: "recording prefix on create", operation: admissionv1.Create, existing: "rec_container_injected"},
		{name: "additional parts on create", operation: admissionv1.Create, existing: "rec_container_abcde_1661693966_x"},
		{name: "empty on create", operation: admissionv1.Create, existing: ""},
		{name: "own recording on update", operation: admissionv1.Update, old: valid, existing: valid, keep: true},
		{
			// The pod was recorded by another recording, which may be
			// gone: this recording must not start on the running pod.
			name:      "other recording on update",
			operation: admissionv1.Update,
			old:       "other_container_abcde_1661693966",
			existing:  "other_container_abcde_1661693966",
			keep:      true,
		},
		{
			name:      "other recording changed on update",
			operation: admissionv1.Update,
			old:       "other_container_abcde_1661693966",
			existing:  valid,
			want:      "other_container_abcde_1661693966",
		},
		{
			name:        "added on update",
			operation:   admissionv1.Update,
			unannotated: true,
			existing:    valid,
			removed:     true,
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
		{name: "empty on update", operation: admissionv1.Update, old: "", existing: "", keep: true},
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
				oldPod := annotatedPod(tc.old)
				if tc.unannotated {
					oldPod = testPod.DeepCopy()
				}

				request.OldObject = rawPod(t, oldPod)
			}

			resp := newTestRecorder(t, mock).Handle(t.Context(), request)
			require.True(t, resp.Allowed)

			if tc.keep && tc.operation == admissionv1.Create {
				// The pod still gets the security context of the recording,
				// for example when the webhook gets invoked again.
				require.Len(t, resp.Patches, 1)
				require.NotContains(t, resp.Patches[0].Path, "/metadata/annotations")

				return
			}

			if tc.keep {
				require.Empty(t, resp.Patches)

				return
			}

			if tc.removed {
				require.Len(t, resp.Patches, 1)
				require.Equal(t, "remove", resp.Patches[0].Operation)
				require.Contains(t, resp.Patches[0].Path, "/metadata/annotations")

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

// The webhook gets invoked again when a later webhook changed the pod, which
// carries the annotation of the recording then. It sends no patches if the
// pod is recorded already, and restores the security context of the recording
// if the other webhook changed it.
func TestHandleReinvocation(t *testing.T) {
	t.Parallel()

	const valid = "rec_container_abcde_1661693966"

	enricherProfile := &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: new(path.Join(
			config.OperatorProfilesFolder,
			config.LogEnricherProfile+seccompprofileapi.ExtJSON,
		)),
	}

	for _, tc := range []struct {
		name    string
		profile *corev1.SeccompProfile
		patched bool
	}{
		{name: "recorded already", profile: enricherProfile},
		{
			name:    "security context changed by another webhook",
			profile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			patched: true,
		},
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

			pod := annotatedPod(valid)
			pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
				SeccompProfile: tc.profile,
			}

			resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, pod),
				},
			})
			require.True(t, resp.Allowed)

			if !tc.patched {
				require.Empty(t, resp.Patches)

				return
			}

			require.Len(t, resp.Patches, 1)
			require.Equal(
				t,
				"/spec/containers/0/securityContext/seccompProfile",
				resp.Patches[0].Path,
			)
			require.Equal(t, map[string]any{
				"type":             string(corev1.SeccompProfileTypeLocalhost),
				"localhostProfile": *enricherProfile.LocalhostProfile,
			}, resp.Patches[0].Value)
		})
	}
}

// Annotations added on update used to be stripped only for the recordings
// which select the pod, so a pod outside of their selectors could start a
// recording of the running pod or rename the recorded profile.
func TestHandleKeepsAnnotationsWithoutMatchingRecording(t *testing.T) {
	t.Parallel()

	const (
		key   = profilerecordingapi.SeccompProfileRecordBpfAnnotationKey + "container"
		value = "rec_container_abcde_1661693966"
	)

	for _, tc := range []struct {
		name     string
		old, new map[string]string
		want     []jsonpatch.Operation
	}{
		{
			name: "added",
			old:  map[string]string{"other": "value"},
			new:  map[string]string{"other": "value", key: value},
			want: []jsonpatch.Operation{{
				Operation: "remove",
				Path:      "/metadata/annotations/io.containers.trace-bpf~1container",
			}},
		},
		{
			name: "changed",
			old:  map[string]string{key: value},
			new:  map[string]string{key: "rec_container_fghij_1661693999"},
			want: []jsonpatch.Operation{{
				// An add replaces an existing member, see addOperation.
				Operation: "add",
				Path:      "/metadata/annotations/io.containers.trace-bpf~1container",
				Value:     value,
			}},
		},
		{
			name: "removed",
			old:  map[string]string{"other": "value", key: value},
			new:  map[string]string{"other": "value"},
			want: []jsonpatch.Operation{{
				Operation: "add",
				Path:      "/metadata/annotations/io.containers.trace-bpf~1container",
				Value:     value,
			}},
		},
		{
			name: "other annotation changed",
			old:  map[string]string{"other": "value", key: value},
			new:  map[string]string{"other": "changed", key: value},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The recording does not select the pod.
			mock := &recordingfakes.FakeImpl{}
			mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
				Items: []profilerecordingapi.ProfileRecording{{
					ObjectMeta: metav1.ObjectMeta{Name: "rec", Namespace: "ns"},
					Spec: profilerecordingapi.ProfileRecordingSpec{
						Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
						Recorder: profilerecordingapi.ProfileRecorderBpf,
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "other"},
						},
					},
				}},
			}, nil)

			oldPod := testPod.DeepCopy()
			oldPod.Annotations = tc.old
			pod := testPod.DeepCopy()
			pod.Annotations = tc.new

			resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
					Object:    rawPod(t, pod),
					OldObject: rawPod(t, oldPod),
				},
			})
			require.True(t, resp.Allowed)
			require.Equal(t, tc.want, resp.Patches)
			require.Len(t, resp.Warnings, len(tc.want))
			// The annotations of the old pod are kept independent of the
			// recordings, so a failing list cannot block pod updates.
			require.Zero(t, mock.ListProfileRecordingsCallCount())
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

// A recording which is being deleted does not record new pods, so that it
// does not keep getting used while pods get created, and the next recording
// which selects the container records it instead.
func TestHandleSkipsRecordingsBeingDeleted(t *testing.T) {
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

	deleting := recording("deleting", 1)
	deleting.DeletionTimestamp = new(metav1.Unix(3, 0))
	deleting.Finalizers = []string{"active-workload-lock"}

	for name, tc := range map[string]struct {
		recordings []profilerecordingapi.ProfileRecording
		recordedBy string
	}{
		"only recording being deleted": {
			recordings: []profilerecordingapi.ProfileRecording{deleting},
		},
		"newer recording records instead": {
			recordings: []profilerecordingapi.ProfileRecording{deleting, recording("newer", 2)},
			recordedBy: "newer",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := &recordingfakes.FakeImpl{}
			mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
				Items: slices.Clone(tc.recordings),
			}, nil)

			resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, testPod.DeepCopy()),
				},
			})
			require.True(t, resp.Allowed)

			if tc.recordedBy == "" {
				require.Empty(t, resp.Patches)

				return
			}

			annotations := slices.DeleteFunc(resp.Patches, func(patch jsonpatch.Operation) bool {
				return !strings.HasPrefix(patch.Path, "/metadata/annotations")
			})
			require.Len(t, annotations, 1)

			value, err := json.Marshal(annotations[0].Value)
			require.NoError(t, err)
			require.Contains(t, string(value), tc.recordedBy+"_container_")
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

// A logs recording used to replace the profile which a binding enforces on
// the container, because the recording webhook runs after the binding
// webhook. Containers bound for the recorded kind are not recorded by the
// logs recorder instead.
func TestHandleSkipsBoundContainers(t *testing.T) {
	t.Parallel()

	binding := func(name, image string, kind profilebindingapi.ProfileBindingKind) profilebindingapi.ProfileBinding {
		return profilebindingapi.ProfileBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{Kind: kind, Name: "profile"},
				Image:      image,
			},
		}
	}

	pod := testPod.DeepCopy()
	pod.Spec.Containers = []corev1.Container{
		{Name: "bound", Image: "bound-image"},
		{Name: "other", Image: "other-image"},
	}

	// The pod author set the recording annotation of the bound container.
	spoofed := pod.DeepCopy()
	spoofed.Annotations = map[string]string{
		"io.containers.trace-logs/bound": "attacker_profile_abcde_1661693966",
	}

	withInit := pod.DeepCopy()
	withInit.Spec.InitContainers = []corev1.Container{{Name: "init", Image: "bound-image"}}

	nginx := testPod.DeepCopy()
	nginx.Spec.Containers = []corev1.Container{
		{Name: "bound", Image: "nginx"},
		{Name: "other", Image: "other-image"},
	}

	for _, tc := range []struct {
		name     string
		kind     profilerecordingapi.ProfileRecordingKind
		recorder profilerecordingapi.ProfileRecorder
		// bindings are applied to the pod and in the cache, unapplied only
		// in the cache and uncached only applied to the pod.
		bindings  []profilebindingapi.ProfileBinding
		unapplied []profilebindingapi.ProfileBinding
		uncached  []string
		// recorded are the containers which get a recording annotation.
		recorded []string
		warnings int
		// pod is the created pod, the test pod if unset.
		pod    *corev1.Pod
		dryRun bool
	}{
		{
			name:     "logs recording removes the annotation of the author on a bound container",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("seccomp", "bound-image", profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"other"},
			warnings: 1,
			pod:      spoofed,
		},
		{
			name:     "logs recording skips the container bound for its kind",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("seccomp", "bound-image", profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"other"},
			warnings: 1,
		},
		{
			name:     "logs recording skips bound init containers",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("seccomp", "bound-image", profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"other"},
			warnings: 2,
			pod:      withInit,
		},
		{
			name:     "logs recording compares the normalized images",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("seccomp", "docker.io/library/nginx:latest",
					profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"other"},
			warnings: 1,
			pod:      nginx,
		},
		{
			name:     "logs recording skips bound containers on a dry run",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("seccomp", "bound-image", profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"other"},
			warnings: 1,
			dryRun:   true,
		},
		{
			name:     "logs recording skips every container of a wildcard binding",
			kind:     profilerecordingapi.ProfileRecordingKindSelinuxProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("selinux", profilebindingapi.SelectAllContainersImage,
					profilebindingapi.ProfileBindingKindSelinuxProfile),
			},
			warnings: 2,
		},
		{
			// The cache of the replica may not know the binding yet, which
			// another replica applied.
			name:     "logs recording skips every container of an uncached binding",
			kind:     profilerecordingapi.ProfileRecordingKindSelinuxProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			uncached: []string{"lagging"},
			warnings: 2,
		},
		{
			name:     "logs recording records containers bound for another kind",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			bindings: []profilebindingapi.ProfileBinding{
				binding("selinux", profilebindingapi.SelectAllContainersImage,
					profilebindingapi.ProfileBindingKindSelinuxProfile),
			},
			recorded: []string{"bound", "other"},
		},
		{
			name:     "logs recording records containers of bindings not applied",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderLogs,
			unapplied: []profilebindingapi.ProfileBinding{
				binding("unapplied", profilebindingapi.SelectAllContainersImage,
					profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"bound", "other"},
		},
		{
			name:     "bpf recording records bound containers",
			kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder: profilerecordingapi.ProfileRecorderBpf,
			bindings: []profilebindingapi.ProfileBinding{
				binding("seccomp", profilebindingapi.SelectAllContainersImage,
					profilebindingapi.ProfileBindingKindSeccompProfile),
			},
			recorded: []string{"bound", "other"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &recordingfakes.FakeImpl{}
			mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
				Items: []profilerecordingapi.ProfileRecording{{
					ObjectMeta: metav1.ObjectMeta{Name: "rec"},
					Spec: profilerecordingapi.ProfileRecordingSpec{
						Kind:        tc.kind,
						Recorder:    tc.recorder,
						PodSelector: selectAll,
					},
				}},
			}, nil)
			mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
				Items: slices.Concat(tc.bindings, tc.unapplied),
			}, nil)

			created := pod.DeepCopy()
			if tc.pod != nil {
				created = tc.pod.DeepCopy()
			}

			applied := slices.Clone(tc.uncached)
			for i := range tc.bindings {
				applied = append(applied, tc.bindings[i].Name)
			}

			if len(applied) > 0 {
				if created.Annotations == nil {
					created.Annotations = map[string]string{}
				}

				created.Annotations[profilebindingapi.AppliedBindingsAnnotation] = strings.Join(
					applied,
					",",
				)
			}

			recorder := events.NewFakeRecorder(10)
			podRecorder := newTestRecorder(t, mock)
			podRecorder.record = utils.NewSafeRecorder(recorder)

			resp := podRecorder.Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, created),
					DryRun:    new(tc.dryRun),
				},
			})
			require.True(t, resp.Allowed)
			require.Len(t, resp.Warnings, tc.warnings)

			if len(tc.uncached) > 0 {
				require.Contains(t, resp.Warnings[0], "not known to the webhook yet")
			}

			if tc.dryRun {
				require.Empty(t, recorder.Events)
			} else {
				require.Len(t, recorder.Events, tc.warnings)
			}

			patched := patchedPod(t, created, resp.Patches)

			var recorded []string

			for _, ctr := range util.PodContainers(patched) {
				for key := range patched.Annotations {
					if strings.HasPrefix(key, "io.containers.trace-") &&
						strings.HasSuffix(key, "/"+ctr.Name) {
						recorded = append(recorded, ctr.Name)
					}
				}

				if !slices.Contains(tc.recorded, ctr.Name) {
					require.Nil(t, ctr.SecurityContext, ctr.Name)
				}
			}

			require.ElementsMatch(t, tc.recorded, recorded)
		})
	}
}

// The webhook gets invoked again on its own output if another webhook changed
// the pod, like the binding webhook restoring a bound profile. The bound
// container stays untouched and the recorded one keeps its annotation.
func TestHandleReinvocationKeepsBoundContainers(t *testing.T) {
	t.Parallel()

	boundProfile := &corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: new("operator/bound.json"),
	}

	pod := testPod.DeepCopy()
	pod.Annotations = map[string]string{profilebindingapi.AppliedBindingsAnnotation: "seccomp"}
	pod.Spec.Containers = []corev1.Container{
		{
			Name:            "bound",
			Image:           "bound-image",
			SecurityContext: &corev1.SecurityContext{SeccompProfile: boundProfile},
		},
		{Name: "other", Image: "other-image"},
	}

	mock := &recordingfakes.FakeImpl{}
	mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
		Items: []profilerecordingapi.ProfileRecording{{
			ObjectMeta: metav1.ObjectMeta{Name: "rec"},
			Spec: profilerecordingapi.ProfileRecordingSpec{
				Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
				Recorder:    profilerecordingapi.ProfileRecorderLogs,
				PodSelector: selectAll,
			},
		}},
	}, nil)
	mock.ListProfileBindingsReturns(&profilebindingapi.ProfileBindingList{
		Items: []profilebindingapi.ProfileBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "seccomp"},
			Spec: profilebindingapi.ProfileBindingSpec{
				ProfileRef: profilebindingapi.ProfileRef{
					Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
					Name: "bound",
				},
				Image: "bound-image",
			},
		}},
	}, nil)

	handle := func(pod *corev1.Pod) admission.Response {
		t.Helper()

		resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object:    rawPod(t, pod),
			},
		})
		require.True(t, resp.Allowed)
		require.Len(t, resp.Warnings, 1)

		return resp
	}

	first := patchedPod(t, pod, handle(pod).Patches)
	require.Equal(t, boundProfile, first.Spec.Containers[0].SecurityContext.SeccompProfile)
	require.NotContains(t, first.Annotations, "io.containers.trace-logs/bound")
	require.Contains(t, first.Annotations, "io.containers.trace-logs/other")

	resp := handle(first)
	require.Empty(t, resp.Patches)
	require.Equal(t, first, patchedPod(t, first, resp.Patches))
}

// The bindings are only listed once a logs recording selects the pod.
func TestHandleListsBindingsOnlyForLogsRecordings(t *testing.T) {
	t.Parallel()

	pod := testPod.DeepCopy()
	pod.Annotations = map[string]string{profilebindingapi.AppliedBindingsAnnotation: "binding"}

	for name, recording := range map[string]profilerecordingapi.ProfileRecordingSpec{
		"no recording selects the pod": {
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: profilerecordingapi.ProfileRecorderLogs,
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "other"},
			},
		},
		"bpf recording": {
			Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder:    profilerecordingapi.ProfileRecorderBpf,
			PodSelector: selectAll,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := &recordingfakes.FakeImpl{}
			mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
				Items: []profilerecordingapi.ProfileRecording{{
					ObjectMeta: metav1.ObjectMeta{Name: "rec"},
					Spec:       recording,
				}},
			}, nil)

			resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
					Object:    rawPod(t, pod),
				},
			})
			require.True(t, resp.Allowed)
			require.Zero(t, mock.ListProfileBindingsCallCount())
		})
	}
}

func TestHandleListBindingsError(t *testing.T) {
	t.Parallel()

	pod := testPod.DeepCopy()
	pod.Annotations = map[string]string{profilebindingapi.AppliedBindingsAnnotation: "binding"}

	mock := &recordingfakes.FakeImpl{}
	mock.ListProfileRecordingsReturns(&profilerecordingapi.ProfileRecordingList{
		Items: []profilerecordingapi.ProfileRecording{{
			ObjectMeta: metav1.ObjectMeta{Name: "rec"},
			Spec: profilerecordingapi.ProfileRecordingSpec{
				Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
				Recorder:    profilerecordingapi.ProfileRecorderLogs,
				PodSelector: selectAll,
			},
		}},
	}, nil)
	mock.ListProfileBindingsReturns(nil, errTest)

	resp := newTestRecorder(t, mock).Handle(t.Context(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    rawPod(t, pod),
		},
	})
	require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
}
