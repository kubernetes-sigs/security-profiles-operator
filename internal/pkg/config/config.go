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
	OperatorName = "security-profiles-operator"

	SPOdServiceAccount = "spod"

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

// GetOperatorNamespace gets the namespace that the operator is currently running on.
func GetOperatorNamespace() string {
	// TODO(jaosorior): Get a method to return the current operator
	// namespace.
	//
	// operatorNs, err := k8sutil.GetOperatorNamespace()
	// if err != nil {
	// 	return "security-profiles-operator"
	// }
	// return operatorNs
	return "security-profiles-operator"
}
