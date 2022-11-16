/*
Copyright 2020 The Kubernetes Authors.

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
	"strings"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

// GetSeccompLocalhostProfilePath returns the path of local seccomp profile
// acording to the runtime.
func GetSeccompLocalhostProfilePath(node *corev1.Node) string {
	containerRuntime := GetContainerRuntime(node)
	// cri-o expects the local seccomp profile to be prefixed with 'localhost'
	// see for more details:
	// https://github.com/cri-o/cri-o/blob/1e6fd9c520d03d47835d1d4c3209e0f77c38f542/internal/config/seccomp/seccomp.go#L240
	if containerRuntime == "cri-o" {
		return path.Join("localhost", bindata.LocalSeccompProfilePath)
	}
	return bindata.LocalSeccompProfilePath
}

// GetContainerRuntime parses the container runtime from a node object.
func GetContainerRuntime(node *corev1.Node) string {
	if node == nil {
		return ""
	}
	containerRuntimeVersion := node.Status.NodeInfo.ContainerRuntimeVersion
	parts := strings.Split(containerRuntimeVersion, ":")
	containerRuntime := ""
	if len(parts) > 0 {
		containerRuntime = parts[0]
	}
	return containerRuntime
}