package util_test

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func TestGetSeccompLocalhostProfilePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		node *corev1.Node
		want string
	}{
		{
			name: "Should return local seccomp profile for cri-o runtime",
			node: &corev1.Node{
				Status: corev1.NodeStatus{
					NodeInfo: corev1.NodeSystemInfo{
						ContainerRuntimeVersion: "cri-o://1.2.3",
					},
				},
			},
			want: path.Join("localhost", bindata.LocalSeccompProfilePath),
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := util.GetSeccompLocalhostProfilePath(tt.node)
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
			name: "should return docker runtime",
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := util.GetContainerRuntime(tt.node)
			require.Equal(t, tt.want, got)
		})
	}
}