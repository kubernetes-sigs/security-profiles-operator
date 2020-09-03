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

package config

const (
	// OperatorName is the name when referring to the operator.
	OperatorName = "seccomp-operator"

	// kubeletSeccompRootPath specifies the path where all kubelet seccomp
	// profiles are stored.
	kubeletSeccompRootPath = "/var/lib/kubelet/seccomp"

	// ProfilesRootPath specifies the path where the operator stores seccomp
	// profiles.
	ProfilesRootPath = kubeletSeccompRootPath + "/operator"

	// DefaultProfilesConfigMapName is the configMap name for the default
	// profiles.
	DefaultProfilesConfigMapName = "default-profiles"

	// CustomProfilesDirectoryName is the directory where profiles from the
	// SeccompProfile CRD are stored.
	CustomProfilesDirectoryName = "custom-profiles"

	// NodeNameEnvKey is the default environment variable key for retrieving
	// the name of the current node.
	NodeNameEnvKey = "NODE_NAME"
)
