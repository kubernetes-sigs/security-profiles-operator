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
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func TestGetSeccompLocalhostProfilePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		node *corev1.Node
		want string
	}{
		{
			name: "Should prefix with localhost the seccomp profile for cri-o runtime for older version",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "cri-o://1.2.3",
						KubeletVersion:          "v1.22.3",
					},
				},
			},
			want: path.Join("localhost", bindata.LocalSeccompProfilePath),
		},
		{
			name: "Should not prefix with localhost the seccomp profile for cri-o runtime for newer version",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "cri-o://1.2.3",
						KubeletVersion:          "v1.24.0",
					},
				},
			},
			want: bindata.LocalSeccompProfilePath,
		},
		{
			name: "Should return local seccomp profile for docker runtime",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "docker://1.2.3",
					},
				},
			},
			want: bindata.LocalSeccompProfilePath,
		},
		{
			name: "Should return local seccomp profile for containerd runtime",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "containerd://1.2.3",
					},
				},
			},
			want: bindata.LocalSeccompProfilePath,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetSeccompLocalhostProfilePath(tt.node, bindata.LocalSeccompProfilePath)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetContainerRuntime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		node *corev1.Node
		want string
	}{
		{
			name: "Should return cri-o runtime",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "cri-o://1.2.3",
					},
				},
			},
			want: "cri-o",
		},
		{
			name: "Should return docker runtime",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "docker://1.2.3",
					},
				},
			},
			want: "docker",
		},
		{
			name: "Should return empty runtime",
			node: nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetContainerRuntime(tt.node)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		node *corev1.Node
		want string
	}{
		{
			name: "Should return the correct version",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						KubeletVersion: "v1.25.3",
					},
				},
			},
			want: "v1.25.3",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetVersion(tt.node)
			require.True(t, semver.IsValid(got), "should return a valid version")
			require.Equal(t, tt.want, got)
		})
	}
}

func TestMatchSelinuxdImageVersion(t *testing.T) {
	t.Parallel()

	mappingJSON := `[
		{
			"regex":"(.*)(CoreOS).*([\\d+])\\.8[\\d+]\\.(.*)",
			"imageFromVar":"RELATED_IMAGE_RHEL8_SELINUXD"
		},
		{
			"regex":"(.*)(CoreOS).*([\\d+])\\.9[\\d+]\\.(.*)",
			"imageFromVar":"RELATED_IMAGE_RHEL9_SELINUXD"
		}
	]`

	tests := []struct {
		name string
		node *corev1.Node
		want string
	}{
		{
			name: "Should return el8",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OSImage: "Red Hat Enterprise Linux CoreOS 411.86.202212072103-0 (Ootpa)",
					},
				},
			},
			want: "RELATED_IMAGE_RHEL8_SELINUXD",
		},
		{
			name: "Should return el9",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OSImage: "CentOS Stream CoreOS 413.92.202303061740-0 (Plow)",
					},
				},
			},
			want: "RELATED_IMAGE_RHEL9_SELINUXD",
		},
		{
			name: "Does not match anything",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						OSImage: "Some other OS",
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := MatchSelinuxdImageJSONMapping(tt.node, []byte(mappingJSON))
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
