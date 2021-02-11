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

package e2e_test

import (
	"fmt"
	"strings"
	"time"
)

func (e *e2e) testCaseSelinuxBaseUsage(nodes []string) {
	e.selinuxtOnlyTestCase()

	const maxNodeIterations = 3
	const sleepBetweenIterations = 5 * time.Second

	// nolint:lll
	const podWithPolicyFmt = `
apiVersion: v1
kind: Pod
metadata:
  name: errorlogger
spec:
  containers:
  - name: errorlogger
    image: "registry.access.redhat.com/ubi8/ubi-minimal:latest"
    command: ["/bin/bash"]
    args: ["-c", "set -eux; while true; do echo \"Time: $(date). Some error info.\" >> /var/log/test.log; sleep 2; done"]
    securityContext:
      seLinuxOptions:
        type: %s
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  restartPolicy: Never
  volumes:
  - name: varlog
    hostPath:
      path: /var/log
      type: Directory
`

	const errorloggerPolicy = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SelinuxPolicy
metadata:
  name: errorlogger
spec:
  apply: true
  policy: |
    (blockinherit container)
    (allow process var_log_t ( dir ( open read getattr lock search ioctl add_name remove_name write ))) 
    (allow process var_log_t ( file ( getattr read write append ioctl lock map open create  ))) 
    (allow process var_log_t ( sock_file ( getattr read write append open  ))) 
`

	e.logf("The 'errorlogger' workload should be able to use SELinux policy")

	e.logf("creating policy")
	e.writeAndCreate(errorloggerPolicy, "errorlogger-policy.yml")

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxpolicy", "errorlogger")

	rawPolicyName := e.getSELinuxPolicyName("errorlogger")

	e.logf("assert policy is installed")

	for i := 0; i < maxNodeIterations; i++ {
		var missingPolName string

		for _, node := range nodes {
			policiesRaw := e.execNode(node, "semodule", "-l")
			if !e.sliceContainsString(strings.Split(policiesRaw, "\n"), rawPolicyName) {
				missingPolName = node
				break
			}
		}

		if missingPolName != "" {
			if i == maxNodeIterations-1 {
				e.Failf("The SelinuxPolicy errorlogger wasn't found in the %s node with the name %s",
					missingPolName, rawPolicyName)
			} else {
				e.logf("the policy was stil present, trying again")
				time.Sleep(sleepBetweenIterations)
			}
		}
	}

	e.logf("creating workload")

	podWithPolicy := fmt.Sprintf(podWithPolicyFmt, e.getSELinuxPolicyUsage("errorlogger"))
	e.writeAndCreate(podWithPolicy, "pod-w-policy.yml")

	e.waitFor("condition=ready", "pod", "errorlogger")

	e.logf("the workload should be running")
	podWithPolicyPhase := e.kubectl(
		"get", "pods", "errorlogger", "-o", "jsonpath={.status.phase}")
	e.Truef(strings.EqualFold(podWithPolicyPhase, "running"),
		"The pod without policy's phase should be 'Running', instead it's: %s",
		podWithPolicyPhase)

	e.logf("cleaning up")

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", "selinuxpolicy", "errorlogger")

	e.logf("assert policy was removed")
	for i := 0; i < maxNodeIterations; i++ {
		var nodeHasPolName string

		for _, node := range nodes {
			policiesRaw := e.execNode(node, "semodule", "-l")
			if e.sliceContainsString(strings.Split(policiesRaw, "\n"), rawPolicyName) {
				nodeHasPolName = node
				break
			}
		}

		if nodeHasPolName != "" {
			if i == maxNodeIterations-1 {
				e.Failf("The SelinuxPolicy errorlogger should have been removed from %s node", nodeHasPolName)
			} else {
				e.logf("the policy was stil present, trying again")
				time.Sleep(sleepBetweenIterations)
			}
		}
	}
}
