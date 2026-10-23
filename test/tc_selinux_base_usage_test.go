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
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	// selinuxWaitTimeout bounds the waits for the policies on the nodes and
	// for the state of the pods which use them.
	selinuxWaitTimeout = 30 * time.Second
	// errorloggerRunTime is how long the errorlogger container has to keep
	// running once its pod is ready. It writes every two seconds and stops
	// at the first write which the policy does not allow.
	errorloggerRunTime = 10 * time.Second
	errorloggerPolicy  = `
apiVersion: security-profiles-operator.x-k8s.io/v1
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
apiVersion: security-profiles-operator.x-k8s.io/v1
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
apiVersion: security-profiles-operator.x-k8s.io/v1
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
apiVersion: security-profiles-operator.x-k8s.io/v1
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

	e.writeAndCreate(policy, "errorlogger-policy.yml")
	// The cleanup below does not run if the test fails.
	e.kubectlCleanup(kind, polName)

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready", kind, polName)

	rawPolicyName := e.getSELinuxPolicyName(kind, polName)

	e.logf("assert policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName)

	e.logf("creating workload")

	podWithPolicy := fmt.Sprintf(podWithPolicyFmt, e.getSELinuxPolicyUsage(kind, polName))

	e.writeAndCreate(podWithPolicy, "pod-w-policy.yml")
	e.kubectlCleanup("pod", "errorlogger")

	e.waitFor("condition=ready", "pod", "errorlogger")

	e.logf("the workload should be running")
	e.assertErrorloggerKeepsRunning()

	e.logf("cleaning up")

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", kind, polName)

	e.logf("assert policy was removed")
	e.assertSelinuxPolicyIsRemoved(nodes, rawPolicyName)
}

func (e *e2e) testCaseSelinuxIncompletePolicy() {
	e.selinuxOnlyTestCase()

	enforcingProfileName := "errorlogger-incomplete-enforcing"

	e.logf("The 'errorlogger' workload should error out with a wrong policy")

	e.logf("creating incomplete policy")

	e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "enforcing", "mode", "Enforcing"),
		"errorlogger-policy-incomplete-enforcing.yml")
	e.kubectlCleanup("selinuxprofile", enforcingProfileName)

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready", "selinuxprofile", enforcingProfileName)

	e.logf("creating workload - it should become ready, but fail")
	podWithPolicy := fmt.Sprintf(
		podWithPolicyFmt,
		e.getSELinuxPolicyUsage("selinuxprofile", enforcingProfileName),
	)
	e.writeAndCreate(podWithPolicy, "pod-w-incomplete-policy.yml")
	e.kubectlCleanup("pod", "errorlogger")

	// note: this would have been much nicer with kubectl wait --jsonpath, but I found it racy incase the status
	// doesn't exist yet. So we're polling instead.
	e.eventually(selinuxWaitTimeout, defaultPollInterval, func() error {
		exitCode := e.kubectl("get", "pods", "errorlogger",
			"-o", "jsonpath={.status.containerStatuses[0].state.terminated.exitCode}")
		if exitCode != "1" {
			return fmt.Errorf("the pod should have failed with exit code 1, got %q", exitCode)
		}

		return nil
	})

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

	e.writeAndCreate(netContainerPolicy, "net-container-policy.yml")
	e.kubectlCleanup("selinuxprofile", netContainerPolicyName)

	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready", "selinuxprofile", netContainerPolicyName)

	rawPolicyName := e.getSELinuxPolicyName("selinuxprofile", netContainerPolicyName)

	e.logf("assert policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName)
}

func (e *e2e) testCaseSelinuxIncompletePermissivePolicy() {
	e.selinuxOnlyTestCase()

	permissiveProfileName := "errorlogger-incomplete-permissive"

	e.logf("The 'errorlogger' workload should run fine with a wrong policy in permissive mode")

	e.logf("creating incomplete policy")

	e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "permissive", "mode", "Permissive"),
		"errorlogger-policy-incomplete-permissive.yml")
	e.kubectlCleanup("selinuxprofile", permissiveProfileName)

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready", "selinuxprofile", permissiveProfileName)

	e.logf("creating workload - it should keep running")
	podWithPolicy := fmt.Sprintf(
		podWithPolicyFmt,
		e.getSELinuxPolicyUsage("selinuxprofile", permissiveProfileName),
	)
	e.writeAndCreate(podWithPolicy, "pod-w-incomplete-permissive-policy.yml")
	e.kubectlCleanup("pod", "errorlogger")

	e.waitFor("condition=ready", "pod", "errorlogger")
	e.assertErrorloggerKeepsRunning()

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", "selinuxprofile", permissiveProfileName)
}

// testCaseSelinuxDeniedPermissivePolicy checks that a SPOD which denies
// permissive profiles keeps a permissive profile from being installed, until
// they are allowed again.
func (e *e2e) testCaseSelinuxDeniedPermissivePolicy(nodes []string) {
	const profileName = "errorlogger-incomplete-denied-permissive"

	e.selinuxOnlyTestCase()

	e.logf("A permissive policy should be rejected while the SPOD denies permissive profiles")

	// The daemons validate the profiles again when the SELinux options
	// change, so there is no rollout to wait for.
	e.kubectlOperatorNS("patch", "spod", "spod", "--type=merge",
		"-p", `{"spec":{"selinux":{"options":{"allowPermissiveProfiles":false}}}}`)
	e.cleanup(func() {
		e.kubectlOperatorNS("patch", "spod", "spod", "--type=merge",
			"-p", `{"spec":{"selinux":{"options":{"allowPermissiveProfiles":null}}}}`)
	})

	e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "denied-permissive", "mode", "Permissive"),
		"errorlogger-policy-denied-permissive.yml")
	e.kubectlCleanup("selinuxprofile", profileName)

	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "jsonpath={.status.status}=Error", "selinuxprofile", profileName)

	e.logf("Allowing permissive profiles again installs the policy")
	e.kubectlOperatorNS("patch", "spod", "spod", "--type=merge",
		"-p", `{"spec":{"selinux":{"options":{"allowPermissiveProfiles":null}}}}`)

	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready", "selinuxprofile", profileName)
	e.assertSelinuxPolicyIsInstalled(nodes, e.getSELinuxPolicyName("selinuxprofile", profileName))
}

func (e *e2e) testCaseSelinuxIncompleteDisabledPolicy() {
	e.selinuxOnlyTestCase()

	disabledProfileName := "errorlogger-incomplete-disabled"

	e.logf("A disabled policy should be possible to install, but not to use")

	e.logf("creating disabled policy")

	e.writeAndCreate(
		fmt.Sprintf(errorloggerIncompletePolFmt, "disabled", "state", "Disabled"),
		"errorlogger-policy-incomplete-disabled.yml")
	e.kubectlCleanup("selinuxprofile", disabledProfileName)

	// Let's wait for the policy to be processed, it will be ready=false
	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready=false", "selinuxprofile", disabledProfileName)

	e.logf("creating workload - it should not even become ready")
	podWithPolicy := fmt.Sprintf(
		podWithPolicyFmt,
		e.getSELinuxPolicyUsage("selinuxprofile", disabledProfileName),
	)
	e.writeAndCreate(podWithPolicy, "pod-w-incomplete-disabled-policy.yml")
	e.kubectlCleanup("pod", "errorlogger")

	// The pod might still be in creating state.
	e.eventually(selinuxWaitTimeout, defaultPollInterval, func() error {
		reason := e.kubectl("get", "pods", "errorlogger",
			"-o", "jsonpath={.status.containerStatuses[0].state.waiting.reason}")
		if reason != "CreateContainerError" {
			return fmt.Errorf(
				"the pod should have failed with CreateContainerError, got %q", reason,
			)
		}

		return nil
	})

	e.logf("removing workload")
	e.kubectl("delete", "pod", "errorlogger")

	e.logf("removing policy")
	e.kubectl("delete", "selinuxprofile", disabledProfileName)
}

// assertErrorloggerKeepsRunning checks that the errorlogger container keeps
// running once its pod is ready and that none of its writes got denied. With
// a policy which does not allow the writes, the pod is ready for a short time
// before the container fails.
func (e *e2e) assertErrorloggerKeepsRunning() {
	e.consistently(errorloggerRunTime, time.Second, func() error {
		status := e.kubectl("get", "pods", "errorlogger", "-o",
			"jsonpath={.status.phase} {.status.containerStatuses[0].restartCount} "+
				"{.status.containerStatuses[0].state.running.startedAt}")

		fields := strings.Fields(status)
		if len(fields) != 3 || fields[0] != "Running" || fields[1] != "0" {
			return fmt.Errorf(
				"the errorlogger container should keep running, "+
					"got phase, restart count and start time %q", status,
			)
		}

		return nil
	})

	log := e.kubectl("logs", "errorlogger", "-c", "errorlogger")
	e.NotContains(log, "Permission denied")
}

func (e *e2e) assertSelinuxPolicyIsInstalled(nodes []string, policy string) {
	e.eventually(selinuxWaitTimeout, defaultPollInterval, func() error {
		for _, node := range nodes {
			policiesRaw := e.execNode(node, "semodule", "-l")
			if !slices.Contains(strings.Split(policiesRaw, "\n"), policy) {
				return fmt.Errorf("the SelinuxProfile %s is not installed on node %s", policy, node)
			}
		}

		return nil
	})
}

func (e *e2e) assertSelinuxPolicyIsRemoved(nodes []string, policy string) {
	e.eventually(selinuxWaitTimeout, defaultPollInterval, func() error {
		for _, node := range nodes {
			policiesRaw := e.execNode(node, "semodule", "-l")
			if slices.Contains(strings.Split(policiesRaw, "\n"), policy) {
				return fmt.Errorf("the SelinuxProfile %s is still on node %s", policy, node)
			}
		}

		return nil
	})
}
