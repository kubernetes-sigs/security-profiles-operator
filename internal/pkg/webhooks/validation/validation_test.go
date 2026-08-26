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

package validation

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, selinuxprofileapi.AddToScheme(scheme))

	return scheme
}

func rawSelinuxProfileRequest(t *testing.T, policy string) admission.Request {
	t.Helper()

	rsp := &selinuxprofileapi.RawSelinuxProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: selinuxprofileapi.GroupVersion.String(),
			Kind:       "RawSelinuxProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-profile",
		},
		Spec: selinuxprofileapi.RawSelinuxProfileSpec{
			Policy: policy,
		},
	}

	raw, err := json.Marshal(rsp)
	require.NoError(t, err)

	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func TestHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		req     func(t *testing.T) admission.Request
		allowed bool
		code    int32
	}{
		{
			name: "valid policy",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(
					t, "(allow process self (tcp_socket (listen)))",
				)
			},
			allowed: true,
		},
		{
			name: "empty policy",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(t, "")
			},
			allowed: false,
		},
		{
			name: "whitespace only policy",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(t, "   ")
			},
			allowed: false,
		},
		{
			name: "unbalanced parentheses",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(
					t, "(allow process self (tcp_socket (listen))",
				)
			},
			allowed: false,
		},
		{
			name: "unmatched closing parenthesis",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(t, ")")
			},
			allowed: false,
		},
		{
			name: "restricted directive block",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(t, "(block test_t)")
			},
			allowed: false,
		},
		{
			name: "restricted directive typepermissive",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(
					t, "(typepermissive test_t)",
				)
			},
			allowed: false,
		},
		{
			name: "null bytes in policy",
			req: func(t *testing.T) admission.Request {
				t.Helper()

				return rawSelinuxProfileRequest(t, "(block test\x00)")
			},
			allowed: false,
		},
		{
			name: "decode error",
			req: func(_ *testing.T) admission.Request {
				return admission.Request{
					AdmissionRequest: admissionv1.AdmissionRequest{
						Operation: admissionv1.Create,
						Object: runtime.RawExtension{
							Raw: []byte("invalid json"),
						},
					},
				}
			},
			allowed: false,
			code:    http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			scheme := newScheme(t)
			v := &rawSelinuxProfileValidator{
				decoder: admission.NewDecoder(scheme),
				log:     logf.Log.WithName("test"),
			}

			resp := v.Handle(context.Background(), tc.req(t))
			require.Equal(t, tc.allowed, resp.Allowed)

			if tc.code != 0 {
				require.NotNil(t, resp.Result)
				require.Equal(t, tc.code, resp.Result.Code)
			}
		})
	}
}
