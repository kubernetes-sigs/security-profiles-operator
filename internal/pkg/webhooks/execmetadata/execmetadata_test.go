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
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func getAdmRequest(t *testing.T, execOpts *corev1.PodExecOptions) admissionv1.AdmissionRequest {
	t.Helper()

	return admissionv1.AdmissionRequest{
		Object: runtime.RawExtension{
			Raw: func() []byte {
				b, err := json.Marshal(execOpts.DeepCopy())
				require.NoError(t, err)

				return b
			}(),
		},
	}
}

func TestHandlePodExecWithContainer(t *testing.T) {
	t.Parallel()

	testExecCall := &corev1.PodExecOptions{
		Container: "test",
		Command:   []string{"echo", "hello"},
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}

	handler := Handler{logr.Discard()}
	resp := handler.Handle(t.Context(), admission.Request{
		AdmissionRequest: getAdmRequest(t, testExecCall),
	})

	if !strings.Contains(resp.Patches[0].Json(), ExecRequestUid) {
		t.Errorf("Expected the response to contain " + ExecRequestUid)
	}
}

func TestHandlePodExecWithoutContainer(t *testing.T) {
	t.Parallel()

	testExecCall := &corev1.PodExecOptions{
		Command: []string{"echo", "hello"},
		Stdin:   true,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}

	handler := Handler{logr.Discard()}
	resp := handler.Handle(t.Context(), admission.Request{
		AdmissionRequest: getAdmRequest(t, testExecCall),
	})

	if !strings.Contains(resp.Patches[0].Json(), ExecRequestUid) {
		t.Errorf("Expected the response to contain " + ExecRequestUid)
	}
}

func TestHandlePodExecMulUid(t *testing.T) {
	t.Parallel()

	testExecCall := &corev1.PodExecOptions{
		Command: []string{
			ExecRequestUid + "=overwriteid",
		},
		Stdin:  true,
		Stdout: true,
		Stderr: true,
		TTY:    true,
	}

	handler := Handler{logr.Discard()}
	resp := handler.Handle(t.Context(), admission.Request{
		AdmissionRequest: getAdmRequest(t, testExecCall),
	})

	if !strings.Contains(resp.Patches[0].Json(), ExecRequestUid) {
		t.Errorf("Expected the response to contain " + ExecRequestUid)
	}

	if strings.Count(resp.Patches[0].Json(), ExecRequestUid) > 1 {
		t.Errorf("Expected only one environment variable" + ExecRequestUid)
	}

	if strings.Count(resp.Patches[0].Json(), "overwriteid") > 1 {
		t.Errorf("Expected overwriteid to be revomed")
	}

	require.Contains(t, resp.AuditAnnotations, ExecRequestUid)
}
