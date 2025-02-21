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
	"encoding/json"
	"fmt"
	"path"
	"time"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func (e *e2e) testCaseAllowedSyscalls(nodes []string) {
	e.testCaseAllowedSyscallsValidation(nodes)
	e.testCaseAllowedSyscallsChange(nodes)
	e.testCaseAllowedSyscallsInUse(nodes)
}

func (e *e2e) testCaseAllowedSyscallsValidation(nodes []string) {
	e.seccompOnlyTestCase()

	const exampleProfilePath = "examples/seccompprofile-allowed-syscalls-validation.yaml"

	e.logf("Changed allowed syscalls list in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}`, "--type=merge")

	defer e.kubectlOperatorNS("patch", "spod", "spod", "--type=json",
		"-p", `[{"op": "remove", "path": "/spec/allowedSyscalls"}]`)
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	allowedProfileNames := []string{"profile-allowed-syscalls", "profile-block-all-syscalls"}
	deniedProfileNames := []string{"profile-denied-syscalls", "profile-allow-all-syscalls"}

	for _, node := range nodes {
		// General operator path verification
		e.logf("Verifying security profiles operator directory on node: %s", node)
		// This symlink is not available on e2e-flatcar because the rootfs is mounted into
		// the dev container where the tests are executed. This check needs to be skipped.
		if e.nodeRootfsPrefix == "" {
			statOutput := e.execNode(
				node, "stat", "-L", "-c", `%a,%u,%g`, config.ProfilesRootPath(),
			)
			e.Contains(statOutput, "744,65535,65535")

			// security-profiles-operator.json init verification
			cm := e.getConfigMap(
				"security-profiles-operator-profile", config.OperatorName,
			)
			e.verifyBaseProfileContent(node, cm)
		}

		for _, name := range allowedProfileNames {
			e.waitFor(
				"condition=ready",
				"seccompprofile", name,
			)

			sp := e.getSeccompProfile(name)
			e.verifyCRDProfileContent(node, sp)

			spns := e.getSeccompProfileNodeStatus(name, node)
			if e.NotNil(spns) {
				e.Equal(spns.Status, secprofnodestatusv1alpha1.ProfileStateInstalled)
			}
		}

		for _, name := range deniedProfileNames {
			e.Falsef(e.existsSeccompProfileNodeStatus(name, node),
				"node status should not be updated for a denied seccomp profile")
		}
	}
}

func (e *e2e) testCaseAllowedSyscallsChange(nodes []string) {
	e.seccompOnlyTestCase()

	const exampleProfilePath = "examples/seccompprofile-allowed-syscalls-change.yaml"
	// Define an allowed syscalls list in the spod configuration
	e.logf("Changed allowed syscalls list in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}`, "--type=merge")

	defer e.kubectlOperatorNS("patch", "spod", "spod",
		"--type=json", "-p", `[{"op": "remove", "path": "/spec/allowedSyscalls"}]`)
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	e.kubectl("create", "-f", exampleProfilePath)

	// Check that the seccomp profile was allowed and installed
	name := "profile-allowed-syscalls"
	e.waitFor(
		"condition=ready",
		"seccompprofile", name,
	)

	sp := e.getSeccompProfile(name)
	for _, node := range nodes {
		e.verifyCRDProfileContent(node, sp)

		spns := e.getSeccompProfileNodeStatus(name, node)
		if e.NotNil(spns) {
			e.Equal(spns.Status, secprofnodestatusv1alpha1.ProfileStateInstalled)
		}
	}

	// Remove a syscall form allowed syscall list in order to invalidate the seccomp profile. The operator
	// should now remove the seccomp profile because is not allowed anymore.
	e.logf("Changed allowed syscalls list in spod to remove syscall")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex"]}}`, "--type=merge")
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	// Wait for profile to be deleted by the operator because it is not allowed anymore by the
	// allowedSyscalls list.
	exists := true
	for range 10 {
		exists = e.existsSeccompProfile(name)
		if !exists {
			break
		}

		time.Sleep(5 * time.Second)
	}

	e.Falsef(exists,
		"seccomp profile should be removed because is not allowed anymore")

	// Check that the seccomp profile file was removed also form the nodes
	for _, node := range nodes {
		profileOperatorPath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())
		e.execNode(node, "test", "!", "-f", profileOperatorPath)
	}
}

func (e *e2e) testCaseAllowedSyscallsInUse(nodes []string) {
	e.seccompOnlyTestCase()

	const (
		allowProfileName = "allow-me"
		allowProfile     = `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: allow-me
spec:
  defaultAction: "SCMP_ACT_ALLOW"
`
		allowPodName = "test-pod"
		allowPod     = `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/allow-me.json
`
	)

	profileCleanup := e.writeAndCreate(allowProfile, "allow-profile*.yaml")
	defer profileCleanup()

	// Check that the seccomp profile was allowed and installed
	e.waitFor(
		"condition=ready",
		"seccompprofile", allowProfileName,
	)

	sp := e.getSeccompProfile(allowProfileName)
	e.Equal(sp.Status.Status, secprofnodestatusv1alpha1.ProfileStateInstalled)

	// Create the pod which reference the allowed profile
	podCleanup := e.writeAndCreate(allowPod, "allow-pod*.yaml")
	defer podCleanup()
	e.waitFor("condition=ready", "pod", allowPodName)

	// Define an allowed syscalls list in the spod configuration, this should disallow the
	// seccomp profile and trigger a deletion.
	e.logf("Changed allowed syscalls list in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}`, "--type=merge")

	defer e.kubectlOperatorNS("patch", "spod", "spod", "--type=json", "-p",
		`[{"op": "remove", "path": "/spec/allowedSyscalls"}]`)
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	// Check that the profile is not deleted while the pod is active but only mark as
	// terminated.
	e.logf("Ensuring profile cannot be deleted while pod is active")

	for range 10 {
		sp := e.getSeccompProfile(allowProfileName)

		conReady := sp.Status.GetReadyCondition()
		if conReady.Reason == spodv1alpha1.ReasonDeleting {
			break
		}

		time.Sleep(time.Second)
	}

	sp = e.getSeccompProfile(allowProfileName)
	e.Equal(sp.Status.Status, secprofnodestatusv1alpha1.ProfileStateTerminating)

	// Remove the pod, after this point the profile should be complete cleaned-up
	e.kubectl("delete", "pod", allowPodName)

	// Wait for profile to be deleted by the operator
	exists := true
	for range 10 {
		exists = e.existsSeccompProfile(allowProfileName)
		if !exists {
			break
		}

		time.Sleep(5 * time.Second)
	}

	e.Falsef(exists,
		"seccomp profile should be removed because is not allowed anymore")

	// Check that the seccomp profile file was removed also form the nodes
	for _, node := range nodes {
		profileOperatorPath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())
		e.execNode(node, "test", "!", "-f", profileOperatorPath)
	}
}

func (e *e2e) existsSeccompProfileNodeStatus(id, node string) bool {
	selector := fmt.Sprintf("spo.x-k8s.io/node-name=%s,spo.x-k8s.io/profile-id=SeccompProfile-%s", node, id)
	seccompProfileNodeStatusJSON := e.kubectl(
		"get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusv1alpha1.SecurityProfileNodeStatusList{}
	e.Nil(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))

	return len(secpolNodeStatusList.Items) > 0
}
