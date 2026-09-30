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
	"fmt"
	"path"
	"slices"
	"time"

	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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
	// Removing the list again must not depend on the rollout succeeding.
	defer e.kubectlOperatorNS("patch", "spod", "spod", "--type=json",
		"-p", `[{"op": "remove", "path": "/spec/security/allowedSyscalls"}]`)

	e.patchSpod(
		`{"spec":{"security":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}}`,
	)

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
				e.Equal(secprofnodestatusapi.ProfileStateInstalled, spns.Status.Status)
			}
		}

		for _, name := range deniedProfileNames {
			e.eventually(time.Minute, 2*time.Second, func() error {
				state, found := e.seccompProfileNodeState(name, node)
				if !found {
					return fmt.Errorf("no node status for denied seccomp profile %s", name)
				}

				if state != secprofnodestatusapi.ProfileStateError {
					return fmt.Errorf("denied seccomp profile %s is in state %s, want %s",
						name, state, secprofnodestatusapi.ProfileStateError)
				}

				return nil
			})
		}
	}
}

func (e *e2e) testCaseAllowedSyscallsChange(nodes []string) {
	e.seccompOnlyTestCase()

	const exampleProfilePath = "examples/seccompprofile-allowed-syscalls-change.yaml"
	// Define an allowed syscalls list in the spod configuration
	e.logf("Changed allowed syscalls list in spod")
	// Removing the list again must not depend on the rollout succeeding.
	defer e.kubectlOperatorNS("patch", "spod", "spod",
		"--type=json", "-p", `[{"op": "remove", "path": "/spec/security/allowedSyscalls"}]`)

	e.patchSpod(
		`{"spec":{"security":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}}`,
	)

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
			e.Equal(secprofnodestatusapi.ProfileStateInstalled, spns.Status.Status)
		}
	}

	// Remove a syscall form allowed syscall list in order to invalidate the seccomp profile. The operator
	// should now remove the seccomp profile because is not allowed anymore.
	e.logf("Changed allowed syscalls list in spod to remove syscall")
	e.patchSpod(`{"spec":{"security":{"allowedSyscalls": ["exit", "exit_group", "futex"]}}}`)

	// Wait for profile to be deleted by the operator because it is not allowed anymore by the
	// allowedSyscalls list.
	e.waitForSeccompProfileRemoved(name)

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
apiVersion: security-profiles-operator.x-k8s.io/v1
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

	e.writeAndCreate(allowProfile, "allow-profile*.yaml")

	// Check that the seccomp profile was allowed and installed
	e.waitFor(
		"condition=ready",
		"seccompprofile", allowProfileName,
	)

	sp := e.getSeccompProfile(allowProfileName)
	e.Equal(secprofnodestatusapi.ProfileStateInstalled, sp.Status.Status)

	// Create the pod which reference the allowed profile
	e.writeAndCreate(allowPod, "allow-pod*.yaml")

	e.waitFor("condition=ready", "pod", allowPodName)

	// The active pod only protects the profile from the deletion below once
	// its finalizer is set, which happens asynchronously.
	e.logf("Waiting for the profile to be marked as in use")
	e.requireEventually(30*time.Second, time.Second, func() error {
		finalizers := e.getSeccompProfile(allowProfileName).Finalizers
		if !slices.Contains(finalizers, util.HasActivePodsFinalizerString) {
			return fmt.Errorf("profile %s not marked as in use: %v", allowProfileName, finalizers)
		}

		return nil
	})

	// Define an allowed syscalls list in the spod configuration, this should disallow the
	// seccomp profile and trigger a deletion.
	e.logf("Changed allowed syscalls list in spod")
	// Removing the list again must not depend on the rollout succeeding.
	defer e.kubectlOperatorNS("patch", "spod", "spod", "--type=json", "-p",
		`[{"op": "remove", "path": "/spec/security/allowedSyscalls"}]`)

	e.patchSpod(
		`{"spec":{"security":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}}`,
	)

	// Check that the profile is not deleted while the pod is active but only mark as
	// terminated.
	e.logf("Ensuring profile cannot be deleted while pod is active")

	e.eventually(time.Minute, time.Second, func() error {
		sp = e.getSeccompProfile(allowProfileName)
		if sp.Status.Status != secprofnodestatusapi.ProfileStateTerminating {
			return fmt.Errorf(
				"profile %s is %q, not %q", allowProfileName,
				sp.Status.Status, secprofnodestatusapi.ProfileStateTerminating,
			)
		}

		return nil
	})

	// Remove the pod, after this point the profile should be complete cleaned-up
	e.kubectl("delete", "pod", allowPodName)

	// Wait for profile to be deleted by the operator
	e.waitForSeccompProfileRemoved(allowProfileName)

	// Check that the seccomp profile file was removed also form the nodes
	for _, node := range nodes {
		profileOperatorPath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())
		e.execNode(node, "test", "!", "-f", profileOperatorPath)
	}
}

// seccompProfileNodeState returns the state of the node status of a seccomp
// profile and whether the node status exists.
// waitForSeccompProfileRemoved waits until the operator removed the seccomp
// profile, which the allowed syscalls do not allow anymore.
func (e *e2e) waitForSeccompProfileRemoved(name string) {
	e.eventually(50*time.Second, 5*time.Second, func() error {
		if e.existsSeccompProfile(name) {
			return fmt.Errorf(
				"seccomp profile %s should be removed because it is not allowed anymore", name,
			)
		}

		return nil
	})
}

func (e *e2e) seccompProfileNodeState(
	id, node string,
) (state secprofnodestatusapi.ProfileState, found bool) {
	selector := fmt.Sprintf(
		"spo.x-k8s.io/node-name=%s,spo.x-k8s.io/profile-id=SeccompProfile-%s",
		node,
		id,
	)
	seccompProfileNodeStatusJSON := e.kubectl(
		"get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	e.Require().NoError(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))

	if len(secpolNodeStatusList.Items) == 0 {
		return "", false
	}

	return secpolNodeStatusList.Items[0].Status.Status, true
}
