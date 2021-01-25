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

import (
	"errors"
	"os"

	"k8s.io/release/pkg/util"
)

const (
	// OperatorName is the name when referring to the operator.
	OperatorName = "security-profiles-operator"

	// KubeletSeccompRootPath specifies the path where all kubelet seccomp
	// profiles are stored.
	KubeletSeccompRootPath = "/var/lib/kubelet/seccomp"

	// ProfilesRootPath specifies the path where the operator stores seccomp
	// profiles.
	ProfilesRootPath = KubeletSeccompRootPath + "/operator"

	// NodeNameEnvKey is the default environment variable key for retrieving
	// the name of the current node.
	NodeNameEnvKey = "NODE_NAME"

	// RestrictNamespaceEnvKey is the environment variable key for restricting
	// the operator to work on only a single Kubernetes namespace.
	RestrictNamespaceEnvKey = "RESTRICT_TO_NAMESPACE"
)

// Controller configMap keys.
const (
	SPOcEnableSelinux = "EnableSelinux"
)

// DaemonSet configMap keys.
const (
	SPOdImagePullPolicy = "SPOdImagePullPolicy"
)

var ErrPodNamespaceEnvNotFound = errors.New("the env variable MY_POD_NAMESPACE hasn't been set")

// GetOperatorNamespace gets the namespace that the operator is currently running on.
func GetOperatorNamespace() (string, error) {
	// This is MY_POD_NAMESPACE should have been set by the downward API to identify
	// the namespace which this controller is running from
	MyPodNamespace := util.EnvDefault("MY_POD_NAMESPACE", "")
	if MyPodNamespace == "" {
		return "", ErrPodNamespaceEnvNotFound
	}
	return MyPodNamespace, nil
}

// GetEnvDefault returns the value of the given environment variable or a
// default value if the given environment variable is not set.
func GetEnvDefault(variable, defaultVal string) string {
	envVar, exists := os.LookupEnv(variable)
	if !exists {
		return defaultVal
	}
	return envVar
}
