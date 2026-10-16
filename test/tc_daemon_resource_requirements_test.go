//go:build e2e

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

package e2e_test

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
)

func (e *e2e) testCaseResourceRequirementsChange([]string) {
	e.restoreSpodSpec()

	e.logf("Change resource requirements in spod")
	e.patchSpod(`{"spec":{"daemonResourceRequirements":
		{"requests": {"memory": "256Mi", "cpu": "250m"},
		"limits": {"memory": "512Mi", "cpu": "500m"}}}}`)

	// Other containers of the DaemonSet already use some of these values by
	// default, so only the resources of the daemon container count.
	const daemonResources = `jsonpath={.spec.template.spec.containers[?(@.name=="security-profiles-operator")].resources}`

	output := e.kubectlOperatorNS("get", "ds", "spod", "-o", daemonResources)

	var resources corev1.ResourceRequirements

	e.Require().NoError(json.Unmarshal([]byte(output), &resources))

	e.Equal("256Mi", resources.Requests.Memory().String())
	e.Equal("250m", resources.Requests.Cpu().String())
	e.Equal("512Mi", resources.Limits.Memory().String())
	e.Equal("500m", resources.Limits.Cpu().String())
}
