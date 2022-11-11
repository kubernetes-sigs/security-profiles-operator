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

package e2e_test

import (
	"time"
)

func (e *e2e) testCaseResourceRequirementsChange([]string) {
	e.logf("Change resource requirements in spod")
	e.kubectlOperatorNS(
		"patch",
		"spod",
		"spod",
		"-p",
		`{"spec":{"daemonResourceRequirements": 
		{"requests": {"memory": "256Mi", "cpu": "250m"}, 
		"limits": {"memory": "512Mi", "cpu": "500m"}}}}`,
		"--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	updatedResourcesInSPODDS := e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")

	e.Contains(updatedResourcesInSPODDS, "256Mi")
	e.Contains(updatedResourcesInSPODDS, "250m")
	e.Contains(updatedResourcesInSPODDS, "512Mi")
	e.Contains(updatedResourcesInSPODDS, "500m")
}
