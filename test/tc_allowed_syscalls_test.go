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
	"path"
	"time"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func (e *e2e) testCaseAllowedSyscalls(nodes []string) {
	e.testCaseAllowedSyscallsValidation(nodes)
	e.testCaseAllowedSyscallsChange(nodes)
}

func (e *e2e) testCaseAllowedSyscallsValidation(nodes []string) {
	e.seccompOnlyTestCase()
	const exampleProfilePath = "examples/seccompprofile-allowed-syscalls-validation.yaml"
	e.logf("Changed allowed syscalls list in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}`, "--type=merge")
	defer e.kubectlOperatorNS("patch", "spod", "spod", "--type=json", "-p", `[{"op": "remove", "path": "/spec/allowedSyscalls"}]`)
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	allowedProfileNames := []string{"profile-allowed-syscalls", "profile-block-all-syscalls"}
	deniedProfileNames := []string{"profile-denied-syscalls", "profile-allow-all-syscalls"}
	for _, node := range nodes {
		e.logf("Verifying security profiles operator directory on node: %s", node)
		statOutput := e.execNode(
			node, "stat", "-L", "-c", `%a,%u,%g`, config.ProfilesRootPath,
		)
		e.Contains(statOutput, "744,65535,65535")

		cm := e.getConfigMap(
			"security-profiles-operator-profile", config.OperatorName,
		)
		e.verifyBaseProfileContent(node, cm)

		for _, name := range allowedProfileNames {
			namespace := e.getCurrentContextNamespace(defaultNamespace)
			e.waitFor(
				"condition=ready",
				"--namespace", namespace,
				"seccompprofile", name,
			)
			sp := e.getSeccompProfile(name, namespace)
			e.verifyCRDProfileContent(node, sp)

			spns := e.getSeccompProfileNodeStatus(name, namespace, node)
			e.Equal(spns.Status, secprofnodestatusv1alpha1.ProfileStateInstalled)
		}

		for _, name := range deniedProfileNames {
			namespace := e.getCurrentContextNamespace(defaultNamespace)
			e.False(e.existsSeccompProfileNodeStatus(name, namespace, node))
		}
	}
}

func (e *e2e) testCaseAllowedSyscallsChange(nodes []string) {
	e.seccompOnlyTestCase()
	const exampleProfilePath = "examples/seccompprofile-allowed-syscalls-change.yaml"
	// Define an allowed syscalls list in the spod configuration
	e.logf("Changed allowed syscalls list in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}`, "--type=merge")
	defer e.kubectlOperatorNS("patch", "spod", "spod", "--type=json", "-p", `[{"op": "remove", "path": "/spec/allowedSyscalls"}]`)
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	// Check that the seccomp profile was allowed and installed
	name := "profile-allowed-syscalls"
	namespace := e.getCurrentContextNamespace(defaultNamespace)
	e.waitFor(
		"condition=ready",
		"--namespace", namespace,
		"seccompprofile", name,
	)
	sp := e.getSeccompProfile(name, namespace)
	for _, node := range nodes {
		e.verifyCRDProfileContent(node, sp)

		spns := e.getSeccompProfileNodeStatus(name, namespace, node)
		e.Equal(spns.Status, secprofnodestatusv1alpha1.ProfileStateInstalled)
	}

	// Remove a syscall form allowed syscall list in order to invalidate the seccomp profile. The operator
	// should now remove the seccomp profile because is not allowed anymore.
	e.logf("Changed allowed syscalls list in spod to remove syscall")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"allowedSyscalls": ["exit", "exit_group", "futex"]}}`, "--type=merge")
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	// Wait for profile to be deleted by the operator because it is not allowed anymore by the
	// allowedSyscalls list.
	exists := true
	for i := 0; i < 10; i++ {
		exists = e.existsSeccompProfile(name, "-n", namespace)
		if !exists {
			break
		}
		time.Sleep(5 * time.Second)
	}
	e.False(exists)

	// Check that the seccomp profile file was removed also form the nodes
	for _, node := range nodes {
		profileOperatorPath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())
		e.execNode(node, "test", "-f", profileOperatorPath)
	}
}

func (e *e2e) existsSeccompProfileNodeStatus(id, namespace, node string) bool {
	selector := fmt.Sprintf("spo.x-k8s.io/node-name=%s,spo.x-k8s.io/profile-id=SeccompProfile-%s", node, id)
	seccompProfileNodeStatusJSON := e.kubectl(
		"-n", namespace, "get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusv1alpha1.SecurityProfileNodeStatusList{}
	e.Nil(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))
	return len(secpolNodeStatusList.Items) > 0
}
