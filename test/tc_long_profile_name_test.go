/*
Copyright 2021 The Kubernetes Authors.

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
	"fmt"
	"strings"
	"time"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
)

const (
	policyName     = "this-is-a-very-long-name-surely-over-64-characters-omg-its-overflowing"
	longNamePolicy = `
    apiVersion: security-profiles-operator.x-k8s.io/v1beta1
    kind: SeccompProfile
    metadata:
      name: this-is-a-very-long-name-surely-over-64-characters-omg-its-overflowing
    spec:
      defaultAction: "SCMP_ACT_ALLOW"
`
)

func (e *e2e) testCaseLongSeccompProfileName(nodes []string) {
	e.logf("List node statuses for a policy with a very long name")

	e.logf("Creating policy")
	deleteFn := e.writeAndCreate(longNamePolicy, "longname-policy.yml")
	defer deleteFn()

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(policyName)

	e.logf("List all node statuses for policy by ID")
	id := e.getSeccompPolicyID(policyName)
	namespace := e.getCurrentContextNamespace(defaultNamespace)
	selector := fmt.Sprintf(
		"spo.x-k8s.io/profile-id in (%s),spo.x-k8s.io/node-name in (%s)",
		id, strings.Join(nodes, ","))

	const maxTries = 10
	for i := 0; i < maxTries; i++ {
		e.logf("Comparing node status items with node length (try %d)", i+1)

		seccompProfileNodeStatusJSON := e.kubectl(
			"-n", namespace, "get", "securityprofilenodestatus", "-l", selector, "-o", "json",
		)

		secpolNodeStatusList := &secprofnodestatusv1alpha1.SecurityProfileNodeStatusList{}
		e.Nil(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))

		if len(nodes) == len(secpolNodeStatusList.Items) {
			e.logf("Node status successfully reconciled")
			return
		}

		time.Sleep(3 * time.Second)
	}

	e.Fail("Node status has not been reconciled successfully")
}
