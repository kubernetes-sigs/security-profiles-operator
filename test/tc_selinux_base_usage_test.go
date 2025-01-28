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
	maxNodeIterations      = 6
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

	rawErrorloggerPolicy = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: RawSelinuxProfile
metadata:
  name: raw-errorlogger
spec:
  policy: |
    (blockinherit container)
    (allow process var_log_t ( dir ( open read getattr lock search ioctl add_name remove_name write )))
    (allow process var_log_t ( file ( getattr read write append ioctl lock map open create  )))
    (allow process var_log_t ( sock_file ( getattr read write append open  )))
`

	// this is the equivalent of errorloggerPolicy but with several calls removed. The idea is to
	// ensure that the workload will fail if the policy in incomplete. Allows setting a parameter
	// as needed.
	errorloggerIncompletePolFmt = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: SelinuxProfile
metadata:
  name: errorlogger-incomplete-%s
spec:
  %s: %s
  allow:
    var_log_t:
      dir:
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

	netContainerPolicy = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: SelinuxProfile
metadata:
  name: net-container-policy
spec:
  inherit:
    - name: net_container
  allow:
    var_run_t:
      sock_file:
        - write
`

	//nolint:lll // full yaml
	podWithPolicyFmt = `
apiVersion: v1
kind: Pod
metadata:
  name: errorlogger
spec:
  containers:
  - name: errorlogger
    image: "registry.access.redhat.com/ubi9/ubi-minimal:latest"
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
	e.selinuxBaseUsage("selinuxprofile", errorloggerPolicy, "errorlogger", nodes)
}

func (e *e2e) testCaseRawSelinuxBaseUsage(nodes []string) {
	e.selinuxBaseUsage("rawselinuxprofile", rawErrorloggerPolicy, "raw-errorlogger", nodes)
}

func (e *e2e) selinuxBaseUsage(kind, policy, polName string, nodes []string) {
	e.selinuxOnlyTestCase()

	e.logf("The 'errorlogger' workload should be able to use SELinux policy")

	e.logf("creating policy")

	rmFn := e.writeAndCreate(policy, "errorlogger-policy.yml")
	defer rmFn()

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", kind, polName)

	rawPolicyName := e.getSELinuxPolicyName(kind, polName)

	e.logf("assert policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)

	e.logf("creating workload")

	podWithPolicy := fmt.Sprintf(podWithPolicyFmt, e.getSELinuxPolicyUsage(kind, polName))
	e.writeAndCreate(podWithPolicy, "pod-w-policy.yml")

	e.waitFor("condition=ready", "pod", polName)

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
	e.kubectl("delete", kind, polName)

	e.logf("assert policy was removed")
	e.assertSelinuxPolicyIsRemoved(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)
}

func (e *e2e) testCaseSelinuxIncompletePolicy() {
	e.selinuxOnlyTestCase()

	enforcingProfileName := "errorlogger-incomplete-enforcing"

	e.logf("The 'errorlogger' workload should error out with a wrong policy")

	e.logf("creating incomplete policy")

	removeFn := e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "enforcing", "permissive", "false"),
		"errorlogger-policy-incomplete-enforcing.yml")
	defer removeFn()

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxprofile", enforcingProfileName)

	e.logf("creating workload - it should become ready, but fail")
	podWithPolicy := fmt.Sprintf(podWithPolicyFmt, e.getSELinuxPolicyUsage("selinuxprofile", enforcingProfileName))
	e.writeAndCreate(podWithPolicy, "pod-w-incomplete-policy.yml")

	// note: this would have been much nicer with kubectl wait --jsonpath, but I found it racy incase the status
	// doesn't exist yet. So we're using a loop instead.
	var exitCode string
	for range 10 {
		exitCode = e.kubectl("get", "pods", "errorlogger",
			"-o", "jsonpath={.status.containerStatuses[0].state.terminated.exitCode}")
		if exitCode == "1" {
			break
		}

		time.Sleep(2 * time.Second)
	}

	if exitCode != "1" {
		e.Fail("The pod should have failed, but it didn't")
	}

	log := e.kubectl("logs", "errorlogger", "-c", "errorlogger")
	e.Contains(log, "Permission denied")

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", "selinuxprofile", enforcingProfileName)
}

func (e *e2e) testCaseSelinuxNonDefaultTemplate(nodes []string) {
	const netContainerPolicyName = "net-container-policy"

	e.selinuxOnlyTestCase()

	e.logf("Should be able to install a policy using a different template than container")
	e.logf("creating policy")

	rmFn := e.writeAndCreate(netContainerPolicy, "net-container-policy.yml")
	defer rmFn()

	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxprofile", netContainerPolicyName)

	rawPolicyName := e.getSELinuxPolicyName("selinuxprofile", netContainerPolicyName)

	e.logf("assert policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)
}

func (e *e2e) testCaseSelinuxIncompletePermissivePolicy() {
	e.selinuxOnlyTestCase()

	permissiveProfileName := "errorlogger-incomplete-permissive"

	e.logf("The 'errorlogger' workload should run fine with a wrong policy in permissive mode")

	e.logf("creating incomplete policy")

	removeFn := e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "permissive", "permissive", "true"),
		"errorlogger-policy-incomplete-permissive.yml")
	defer removeFn()

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxprofile", permissiveProfileName)

	e.logf("creating workload - it should become ready, but fail")
	podWithPolicy := fmt.Sprintf(podWithPolicyFmt, e.getSELinuxPolicyUsage("selinuxprofile", permissiveProfileName))
	e.writeAndCreate(podWithPolicy, "pod-w-incomplete-permissive-policy.yml")

	e.waitFor("condition=ready", "pod", "errorlogger")

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", "selinuxprofile", permissiveProfileName)
}

func (e *e2e) testCaseSelinuxIncompleteDisabledPolicy() {
	e.selinuxOnlyTestCase()

	disabledProfileName := "errorlogger-incomplete-disabled"

	e.logf("A disabled policy should be possible to install, but not to use")

	e.logf("creating disabled policy")

	removeFn := e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "disabled", "disabled", "true"),
		"errorlogger-policy-incomplete-disabled.yml")
	defer removeFn()

	// Let's wait for the policy to be processed, it will be ready=false
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready=false", "selinuxprofile", disabledProfileName)

	e.logf("creating workload - it should not even become ready")
	podWithPolicy := fmt.Sprintf(podWithPolicyFmt, e.getSELinuxPolicyUsage("selinuxprofile", disabledProfileName))
	e.writeAndCreate(podWithPolicy, "pod-w-incomplete-disabled-policy.yml")

	var exitCode string
	for range 10 {
		// loop a few times, because the pod might be in creating state
		exitCode = e.kubectl("get", "pods", "errorlogger",
			"-o", "jsonpath={.status.containerStatuses[0].state.waiting.reason}")
		if exitCode == "CreateContainerError" {
			break
		}

		time.Sleep(2 * time.Second)

		continue
	}

	if exitCode != "CreateContainerError" {
		e.Fail("The pod should have failed, but it didn't")
	}

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", "selinuxprofile", disabledProfileName)
}

func (e *e2e) assertSelinuxPolicyIsInstalled(nodes []string, policy string, nodeIterations int, sleep time.Duration) {
	for i := range nodeIterations {
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
				e.Fail(fmt.Sprintf(
					"The SelinuxProfile wasn't found in the %s node with the name %s",
					missingPolName, policy,
				))
			} else {
				e.logf("the policy was still present, trying again")
				time.Sleep(sleep)
			}
		}
	}
}

func (e *e2e) assertSelinuxPolicyIsRemoved(nodes []string, policy string, nodeIterations int, sleep time.Duration) {
	for i := range nodeIterations {
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
				e.Fail(fmt.Sprintf(
					"The SelinuxProfile was found in the %s node with the name %s",
					missingPolName, policy,
				))
			} else {
				e.logf("the policy was still present, trying again")
				time.Sleep(sleep)
			}
		}
	}
}
