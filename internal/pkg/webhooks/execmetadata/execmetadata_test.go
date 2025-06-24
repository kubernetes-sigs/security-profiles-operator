/*
Copyright 2025 The Kubernetes Authors.

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

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func getPodEphAdmRequest(t *testing.T, execOpts *corev1.Pod) admissionv1.AdmissionRequest {
	t.Helper()

	return admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{
			Kind: "Pod",
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

func getPodExecAdmRequest(t *testing.T, execOpts *corev1.PodExecOptions) admissionv1.AdmissionRequest {
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
			name:   "Basic Test for Pod Debug",
			fields: fields{log: logr.Discard()},
			args: args{t.Context(), admission.Request{
				AdmissionRequest: getPodEphAdmRequest(t, &corev1.Pod{
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
				}),
			}},
			want: admission.Response{
				Patches: []jsonpatch.JsonPatchOperation{
					{
						Operation: "replace",
						Path:      "/spec/ephemeralContainers/0/env",
						Value:     []corev1.EnvVar{{Name: "SPO_EXEC_REQUEST_UID", Value: "test-uid"}},
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
				AdmissionRequest: getPodEphAdmRequest(t, &corev1.Pod{
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
				}),
			}},
			want: admission.Response{
				Patches: []jsonpatch.JsonPatchOperation{
					{
						Operation: "replace",
						Path:      "/spec/ephemeralContainers/0/env",
						Value:     []corev1.EnvVar{{Name: "SPO_EXEC_REQUEST_UID", Value: "test-uid"}},
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
				Patches: []jsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/command",
						Value:     []string{"env", "SPO_EXEC_REQUEST_UID=test-uid", "echo", "hello"},
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
				Patches: []jsonpatch.JsonPatchOperation{
					{
						Operation: "add",
						Path:      "/command",
						Value:     []string{"env", "SPO_EXEC_REQUEST_UID=test-uid", "echo", "hello"},
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
