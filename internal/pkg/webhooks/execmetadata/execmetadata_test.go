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

package execmetadata

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	gomodulesjsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// getPodAdmRequest returns a pod admission request like the API server sends
// it, with the sub resource separate from the resource.
func getPodAdmRequest(
	t *testing.T, pod *corev1.Pod, subResource string,
) admissionv1.AdmissionRequest {
	t.Helper()

	return admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{
			Version: "v1",
			Kind:    "Pod",
		},
		Resource: metav1.GroupVersionResource{
			Version:  "v1",
			Resource: "pods",
		},
		SubResource: subResource,
		Object: runtime.RawExtension{
			Raw: func() []byte {
				b, err := json.Marshal(pod.DeepCopy())
				require.NoError(t, err)

				return b
			}(),
		},
	}
}

func getPodExecAdmRequest(
	t *testing.T,
	execOpts *corev1.PodExecOptions,
) admissionv1.AdmissionRequest {
	t.Helper()

	return admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{
			Kind: "PodExecOptions",
		},
		Object: runtime.RawExtension{
			Raw: func() []byte {
				b, err := json.Marshal(execOpts.DeepCopy())
				require.NoError(t, err)

				return b
			}(),
		},
	}
}

func TestHandler_Handle(t *testing.T) {
	t.Parallel()

	type fields struct {
		log logr.Logger
	}

	type args struct {
		//nolint:containedctx // Only for unit testing
		in0 context.Context
		req admission.Request
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		want   admission.Response
	}{
		{
			name:   "Basic Test for Node Debugging Pod",
			fields: fields{log: logr.Discard()},
			args: args{t.Context(), admission.Request{
				AdmissionRequest: getPodAdmRequest(t, &corev1.Pod{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "debugger",
							},
						},
					},
				}, ""),
			}},
			want: admission.Response{
				Patches: []gomodulesjsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/spec/containers/0/env",
						Value: []corev1.EnvVar{
							{Name: "SPO_EXEC_REQUEST_UID", Value: "test-uid"},
						},
					},
				},
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result: &metav1.Status{
						Code:    200,
						Message: "UID added to execmetadata",
					},
					AuditAnnotations: map[string]string{
						ExecRequestUid: "test-uid",
					},
				},
			},
		},
		{
			name:   "Basic Test for Pod Debug",
			fields: fields{log: logr.Discard()},
			args: args{t.Context(), admission.Request{
				AdmissionRequest: getPodAdmRequest(t, &corev1.Pod{
					Spec: corev1.PodSpec{
						EphemeralContainers: []corev1.EphemeralContainer{
							{
								EphemeralContainerCommon: corev1.EphemeralContainerCommon{
									Name: "debug-1",
								},
								TargetContainerName: "test",
							},
						},
					},
				}, ephemeralContainersSubResource),
			}},
			want: admission.Response{
				Patches: []gomodulesjsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/spec/ephemeralContainers/0/env",
						Value: []corev1.EnvVar{
							{Name: "SPO_EXEC_REQUEST_UID", Value: "test-uid"},
						},
					},
				},
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result: &metav1.Status{
						Code:    200,
						Message: "UID added to execmetadata",
					},
					AuditAnnotations: map[string]string{
						ExecRequestUid: "test-uid",
					},
				},
			},
		},
		{
			name:   "Duplicate Test for Pod Debug",
			fields: fields{log: logr.Discard()},
			args: args{t.Context(), admission.Request{
				AdmissionRequest: getPodAdmRequest(t, &corev1.Pod{
					Spec: corev1.PodSpec{
						EphemeralContainers: []corev1.EphemeralContainer{
							{
								EphemeralContainerCommon: corev1.EphemeralContainerCommon{
									Name: "debug-1",
									Env: []corev1.EnvVar{
										{
											Name:  "SPO_EXEC_REQUEST_UID",
											Value: "overwritethis",
										},
									},
								},
								TargetContainerName: "test",
							},
						},
					},
				}, ephemeralContainersSubResource),
			}},
			want: admission.Response{
				Patches: []gomodulesjsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/spec/ephemeralContainers/0/env",
						Value: []corev1.EnvVar{
							{Name: "SPO_EXEC_REQUEST_UID", Value: "test-uid"},
						},
					},
				},
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result: &metav1.Status{
						Code:    200,
						Message: "UID added to execmetadata",
					},
					AuditAnnotations: map[string]string{
						ExecRequestUid: "test-uid",
					},
				},
			},
		},
		{
			name:   "Basic Test for PodExec",
			fields: fields{log: logr.Discard()},
			args: args{t.Context(), admission.Request{
				AdmissionRequest: getPodExecAdmRequest(t, &corev1.PodExecOptions{
					Command: []string{"echo", "hello"},
					Stdin:   true,
					Stdout:  true,
					Stderr:  true,
					TTY:     true,
				}),
			}},
			want: admission.Response{
				Patches: []gomodulesjsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/command",
						Value: []string{
							"env",
							"SPO_EXEC_REQUEST_UID=test-uid",
							"echo",
							"hello",
						},
					},
				},
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result: &metav1.Status{
						Code:    200,
						Message: "UID added to execmetadata",
					},
					AuditAnnotations: map[string]string{
						ExecRequestUid: "test-uid",
					},
				},
			},
		},
		{
			name:   "Having duplicate env vars Test",
			fields: fields{log: logr.Discard()},
			args: args{t.Context(), admission.Request{
				AdmissionRequest: getPodExecAdmRequest(t, &corev1.PodExecOptions{
					Command: []string{"env", ExecRequestUid + "=overwrite", "echo", "hello"},
					Stdin:   true,
					Stdout:  true,
					Stderr:  true,
					TTY:     true,
				}),
			}},
			want: admission.Response{
				Patches: []gomodulesjsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/command",
						Value: []string{
							"env",
							"SPO_EXEC_REQUEST_UID=test-uid",
							"echo",
							"hello",
						},
					},
				},
				AdmissionResponse: admissionv1.AdmissionResponse{
					Allowed: true,
					Result: &metav1.Status{
						Code:    200,
						Message: "UID added to execmetadata",
					},
					AuditAnnotations: map[string]string{
						ExecRequestUid: "test-uid",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := Handler{
				log: tt.fields.log,
			}
			if got := p.Handle(tt.args.in0, tt.args.req); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Handle() = %v, want %v", got, tt.want)

				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("response mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestHandlerPatchAppliesToContainerWithoutEnv pins down why the patch uses
// "add" and not "replace". Container.Env is omitempty, so a container that
// declares no environment has no /spec/containers/0/env member at all, and RFC
// 6902 makes "replace" on a missing member an error. Asserting the expected
// operation literal alone would not catch a regression here: this test applies
// the produced patch to the original object, which fails outright if the
// operation is wrong.
func TestHandlerPatchAppliesToContainerWithoutEnv(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		resource string
		pod      *corev1.Pod
	}{
		{
			name:     "node debugging pod without env",
			resource: "",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "debugger"}},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := admission.Request{AdmissionRequest: getPodAdmRequest(t, tc.pod, tc.resource)}

			resp := Handler{log: logr.Discard()}.Handle(t.Context(), req)
			require.True(t, resp.Allowed)
			require.NotEmpty(t, resp.Patches)

			raw, err := json.Marshal(resp.Patches)
			require.NoError(t, err)

			patch, err := jsonpatch.DecodePatch(raw)
			require.NoError(t, err)

			patched, err := patch.Apply(req.Object.Raw)
			require.NoError(t, err, "the produced patch must be applicable to the original object")

			result := &corev1.Pod{}
			require.NoError(t, json.Unmarshal(patched, result))
			require.Len(t, result.Spec.Containers, 1)
			require.Contains(t, result.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  ExecRequestUid,
				Value: "test-uid",
			})
		})
	}
}

// Only ephemeral containers which get added by the request must be patched,
// because the env of existing ones cannot be changed anymore.
func TestHandlerPatchesOnlyNewEphemeralContainers(t *testing.T) {
	t.Parallel()

	ephemeral := func(name string) corev1.EphemeralContainer {
		return corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: name},
		}
	}

	oldPod := &corev1.Pod{
		Spec: corev1.PodSpec{
			EphemeralContainers: []corev1.EphemeralContainer{ephemeral("existing")},
		},
	}
	newPod := oldPod.DeepCopy()
	newPod.Spec.EphemeralContainers = append(newPod.Spec.EphemeralContainers, ephemeral("new"))

	req := getPodAdmRequest(t, newPod, ephemeralContainersSubResource)
	req.Operation = admissionv1.Update
	req.OldObject = runtime.RawExtension{Raw: func() []byte {
		b, err := json.Marshal(oldPod)
		require.NoError(t, err)

		return b
	}()}

	resp := Handler{
		log: logr.Discard(),
	}.Handle(
		t.Context(),
		admission.Request{AdmissionRequest: req},
	)
	require.True(t, resp.Allowed)
	require.Len(t, resp.Patches, 1)
	require.Equal(t, "/spec/ephemeralContainers/1/env", resp.Patches[0].Path)
}

func TestHandlerIgnoresOtherSubResources(t *testing.T) {
	t.Parallel()

	resp := Handler{log: logr.Discard()}.Handle(t.Context(), admission.Request{
		AdmissionRequest: getPodAdmRequest(t, &corev1.Pod{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "ctr"}}},
		}, "status"),
	})

	require.True(t, resp.Allowed)
	require.Empty(t, resp.Patches)
	require.Equal(t, "pod exec request unmodified", resp.Result.Message)
}
