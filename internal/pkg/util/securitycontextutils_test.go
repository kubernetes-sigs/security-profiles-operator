/*
Copyright 2022 The Kubernetes Authors.

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

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestPatchSecurityContext(t *testing.T) {
	t.Parallel()

	truely := true
	intValue := int64(1000)
	stringValue := "test"
	procMount := corev1.ProcMountType("test")
	cases := []struct {
		name  string
		base  *corev1.SecurityContext
		patch *corev1.SecurityContext
		want  *corev1.SecurityContext
	}{
		{
			name:  "nil contexts",
			base:  nil,
			patch: nil,
			want:  nil,
		},
		{
			name: "nil patch",
			base: &corev1.SecurityContext{
				RunAsNonRoot: &truely,
			},
			patch: nil,
			want: &corev1.SecurityContext{
				RunAsNonRoot: &truely,
			},
		},
		{
			name: "patch nil SELinuxOptions",
			base: &corev1.SecurityContext{},
			patch: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
			},
			want: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
			},
		},
		{
			name: "patch SELinuxOptions",
			base: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "base_type",
				},
			},
			patch: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
			},
			want: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
			},
		},
		{
			name: "patch only nil fields",
			base: &corev1.SecurityContext{
				RunAsNonRoot:           &truely,
				ReadOnlyRootFilesystem: &truely,
			},
			patch: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
			},
			want: &corev1.SecurityContext{
				RunAsNonRoot:           &truely,
				ReadOnlyRootFilesystem: &truely,
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
			},
		},
		{
			name: "patch all fields",
			base: &corev1.SecurityContext{},
			patch: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add:  []corev1.Capability{"nothing"},
					Drop: []corev1.Capability{"all"},
				},
				Privileged: &truely,
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
				WindowsOptions: &corev1.WindowsSecurityContextOptions{
					HostProcess: &truely,
				},
				RunAsUser:                &intValue,
				RunAsGroup:               &intValue,
				RunAsNonRoot:             &truely,
				ReadOnlyRootFilesystem:   &truely,
				AllowPrivilegeEscalation: &truely,
				ProcMount:                &procMount,
				SeccompProfile: &corev1.SeccompProfile{
					LocalhostProfile: &stringValue,
				},
			},
			want: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add:  []corev1.Capability{"nothing"},
					Drop: []corev1.Capability{"all"},
				},
				Privileged: &truely,
				SELinuxOptions: &corev1.SELinuxOptions{
					Type: "path_type",
				},
				WindowsOptions: &corev1.WindowsSecurityContextOptions{
					HostProcess: &truely,
				},
				RunAsUser:                &intValue,
				RunAsGroup:               &intValue,
				RunAsNonRoot:             &truely,
				ReadOnlyRootFilesystem:   &truely,
				AllowPrivilegeEscalation: &truely,
				ProcMount:                &procMount,
				SeccompProfile: &corev1.SeccompProfile{
					LocalhostProfile: &stringValue,
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := PatchSecurityContext(tc.base, tc.patch)
			require.Equal(t, tc.want, got)
		})
	}
}
