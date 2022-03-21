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

const (
	maxNodeIterations      = 3
	sleepBetweenIterations = 5 * time.Second
	errorloggerPolicy      = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: SelinuxProfile
metadata:
  name: errorlogger
spec:
  allow:
    var_log_t:
      dir:
        - open
        - read
        - getattr
        - lock
        - search
        - ioctl
        - add_name
        - remove_name
        - write
      file:
        - getattr
        - read
        - write
        - append
        - ioctl
        - lock
        - map
        - open
        - create
      sock_file:
        - getattr
        - read
        - write
        - append
        - open
`

	// nolint:lll // full yaml
	podWithPolicyFmt = `
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
)

func (e *e2e) testCaseSelinuxBaseUsage(nodes []string) {
	e.selinuxOnlyTestCase()

	e.logf("The 'errorlogger' workload should be able to use SELinux policy")

	e.logf("creating policy")
	e.writeAndCreate(errorloggerPolicy, "errorlogger-policy.yml")

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxprofile", "errorlogger")

	rawPolicyName := e.getSELinuxPolicyName("errorlogger")

	e.logf("assert policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)

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
	e.kubectl("delete", "selinuxprofile", "errorlogger")

	e.logf("assert policy was removed")
	e.assertSelinuxPolicyIsRemoved(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)
}

func (e *e2e) assertSelinuxPolicyIsInstalled(nodes []string, policy string, nodeIterations int, sleep time.Duration) {
	for i := 0; i < nodeIterations; i++ {
		var missingPolName string

		for _, node := range nodes {
			policiesRaw := e.execNode(node, "semodule", "-l")
			if !e.sliceContainsString(strings.Split(policiesRaw, "\n"), policy) {
				missingPolName = node
				break
			}
		}

		if missingPolName != "" {
			if i == nodeIterations-1 {
				e.Failf("The SelinuxProfile errorlogger wasn't found in the %s node with the name %s",
					missingPolName, policy)
			} else {
				e.logf("the policy was stil present, trying again")
				time.Sleep(sleep)
			}
		}
	}
}

func (e *e2e) assertSelinuxPolicyIsRemoved(nodes []string, policy string, nodeIterations int, sleep time.Duration) {
	for i := 0; i < nodeIterations; i++ {
		var missingPolName string

		for _, node := range nodes {
			policiesRaw := e.execNode(node, "semodule", "-l")
			if e.sliceContainsString(strings.Split(policiesRaw, "\n"), policy) {
				missingPolName = node
				break
			}
		}

		if missingPolName != "" {
			if i == nodeIterations-1 {
				e.Failf("The SelinuxProfile errorlogger was found in the %s node with the name %s",
					missingPolName, policy)
			} else {
				e.logf("the policy was stil present, trying again")
				time.Sleep(sleep)
			}
		}
	}
}
