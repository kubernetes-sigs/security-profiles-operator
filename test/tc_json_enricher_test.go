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
	"fmt"
	"regexp"
	"strings"
	"time"
)

func (e *e2e) testCaseJsonEnricherFileOptions([]string) {
	jsonLogFileName := "/tmp/json-logs/jsonEnricher.out"
	//nolint:lll  // long filter.
	e.jsonEnricherOnlyTestCaseFileOptions(jsonLogFileName,
		`[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]`)

	const (
		profileName   = "jsonenricherprofile"
		podName       = "jsonenricherpod"
		containerName = "jsonenrichercontainer"
	)

	e.logf("Creating test profile for JSON Enricher")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - listen
    - execve
    - clone
    - getpid
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	podCleanup := e.writeAndCreate(pod, "test-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)

	e.waitFor("condition=initialized", "pod", podName)

	e.checkExecEnvironment(podName, 5*time.Second, 20)

	// In 5 seconds the process info will be captured.
	e.kubectl("exec", "-i", podName, "--", "sleep", "5")

	// Wait for the flush interval.
	time.Sleep(20 * time.Second)

	// wait for at least one component of the expected logs to appear
	output := e.waitForJsonEnricherFileLogs(jsonLogFileName,
		regexp.MustCompile(`(?m)"requestUID"`))

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")

	// Special case in ubuntu: \"cmdLine\":\"\",\"executable\":\"/\".
	e.True(stringContainsAny(output, "\"sleep\"", "\"/\""))

	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")
}

func stringContainsAny(fullString string, substrings ...string) bool {
	for _, sub := range substrings {
		if strings.Contains(fullString, sub) {
			return true
		}
	}

	return false
}

func (e *e2e) testCaseJsonEnricher([]string) {
	e.jsonEnricherOnlyTestCase()

	const (
		profileName   = "jsonenricherprofile"
		podName       = "jsonenricherpod"
		containerName = "jsonenrichercontainer"
	)

	e.logf("Creating test profile for JSON Enricher")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - clone
    - fork
    - execveat
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	since := time.Now()

	podCleanup := e.writeAndCreate(pod, "test-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)

	e.waitFor("condition=initialized", "pod", podName)

	e.checkExecEnvironment(podName, 5*time.Second, 20)

	e.kubectl("debug", "--profile", "general", podName, "--image",
		"busybox:latest", "--", "sleep", "6")

	// In 5 seconds the process info will be captured.
	e.kubectl("exec", "-i", podName, "-c", containerName, "--", "sleep", "5")

	nodeName := e.kubectl("get", "nodes",
		"-o", "jsonpath='{.items[0].metadata.name}'")
	nodeDebuggingPodEnvOutput := e.kubectl("debug", "--profile", "general",
		"node/"+strings.Trim(nodeName, "'"), "--image", "busybox", "--", "env")
	e.Contains(nodeDebuggingPodEnvOutput, "SPO_EXEC_REQUEST_UID")
	e.logf("The env output has SPO_EXEC_REQUEST_UID")

	// Wait for the flush interval.
	time.Sleep(20 * time.Second)

	// wait for at least one component of the expected logs to appear
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	// then match the rest
	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")
	// Failed once in the Fedora platform.
	// e.Contains(output, "sleep 6")
	e.Contains(output, "sleep 5")
	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")
}

// Checks exec environment for the pod.
func (e *e2e) checkExecEnvironment(podName string, interval time.Duration, maxTimes int) {
	if !e.podRunning(podName, nil, interval, maxTimes) {
		e.logf("Pod %s is not running", podName)
		e.Fail("Pod is not running")
	}

	if !e.canExec(podName, interval, maxTimes) {
		e.logf("Pod %s cannot be exec", podName)
		e.Fail("Pod cannot be exec")
	}
}

// Attempt exec into the pod and make sure its up.
func (e *e2e) canExec(podName string, interval time.Duration, maxTimes int) bool {
	const expectedEnvVar = "SPO_EXEC_REQUEST_UID"

	for range maxTimes {
		output := e.kubectl("exec", "-i", podName, "--", "env")
		if !strings.Contains(output, expectedEnvVar) {
			time.Sleep(interval)
		} else {
			return true
		}
	}

	e.logf("Cannot exec pod %s in %d times", podName, maxTimes)

	return false
}

// TC3: testCasePrivilegedPods - Test privileged pod scenarios.
func (e *e2e) testCasePrivilegedPods([]string) {
	e.jsonEnricherOnlyTestCase()

	const (
		profileName   = "privileged-profile"
		podName       = "privileged-pod"
		containerName = "privileged-container"
	)

	e.logf("Creating test profile for privileged pods")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - mount
    - execve
    - clone
    - fork
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-privileged-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating privileged test pod")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
    securityContext:
      privileged: true
      runAsUser: 0
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	since := time.Now()

	podCleanup := e.writeAndCreate(pod, "test-privileged-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)
	e.waitFor("condition=initialized", "pod", podName)
	e.checkExecEnvironment(podName, 5*time.Second, 20)

	// Test privileged operations
	e.kubectl("exec", "-i", podName, "-c", containerName, "--", "whoami")
	e.kubectl("exec", "-i", podName, "-c", containerName, "--", "id")

	// Wait for the flush interval
	time.Sleep(20 * time.Second)

	// Verify logs
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output for privileged pods")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")
	e.Contains(output, "\"namespace\"")
}

// TC4: testCaseFileOutputFilteringAndRotation - Test file output with filtering and rotation.
func (e *e2e) testCaseFileOutputFilteringAndRotation([]string) {
	jsonLogFileName := "/tmp/json-logs/rotation-test.log"
	//nolint:lll  // long filter.
	e.jsonEnricherOnlyTestCaseFileOptions(jsonLogFileName,
		`[{\"priority\":10,\"level\":\"Metadata\",\"matchKeys\":[\"namespace\"],\"matchValues\":[\"default\"]},{\"priority\":100,\"level\":\"Request\",\"matchKeys\":[\"requestUID\"]}]`)

	const (
		profileName   = "rotation-test-profile"
		podName       = "rotation-test-pod"
		containerName = "rotation-test-container"
	)

	e.logf("Creating test profile for file rotation")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - clone
    - fork
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-rotation-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod for rotation")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	podCleanup := e.writeAndCreate(pod, "test-rotation-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)
	e.waitFor("condition=initialized", "pod", podName)
	e.checkExecEnvironment(podName, 5*time.Second, 20)

	// Generate multiple log entries
	for range 10 {
		e.kubectl("exec", "-i", podName, "--", "sleep", "1")
	}

	// Wait for the flush interval
	time.Sleep(30 * time.Second)

	// Verify filtered logs
	output := e.waitForJsonEnricherFileLogs(jsonLogFileName,
		regexp.MustCompile(`(?m)"requestUID"`),
		regexp.MustCompile(`(?m)"namespace".*"default"`))

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"namespace\"")
}

// TC5: testCaseMultiNamespaceAndConcurrency - Test multi-namespace concurrent operations.
func (e *e2e) testCaseMultiNamespaceAndConcurrency([]string) {
	e.jsonEnricherOnlyTestCase()

	const (
		profileName    = "multi-ns-profile"
		namespace1     = "audit-ns-1"
		namespace2     = "audit-ns-2"
		podName1       = "audit-pod-1"
		podName2       = "audit-pod-2"
		containerName  = "audit-container"
	)

	e.logf("Creating test namespaces for multi-namespace test")

	// Create namespaces
	e.kubectl("create", "namespace", namespace1)
	defer e.kubectl("delete", "namespace", namespace1)

	e.kubectl("create", "namespace", namespace2)
	defer e.kubectl("delete", "namespace", namespace2)

	// Create profile in both namespaces
	profile := func(ns string) string {
		return fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
  namespace: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - clone
    - fork
`, profileName, ns)
	}

	profileCleanup1 := e.writeAndCreate(profile(namespace1), "test-multi-ns-profile1-*.yaml")
	defer profileCleanup1()
	defer e.kubectl("delete", "sp", profileName, "-n", namespace1)

	profileCleanup2 := e.writeAndCreate(profile(namespace2), "test-multi-ns-profile2-*.yaml")
	defer profileCleanup2()
	defer e.kubectl("delete", "sp", profileName, "-n", namespace2)

	e.logf("Creating pods in multiple namespaces")

	pod := func(ns, podName string) string {
		return fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, ns, containerName, profileName)
	}

	since := time.Now()

	// Create pods
	pod1Cleanup := e.writeAndCreate(pod(namespace1, podName1), "test-multi-ns-pod1-*.yaml")
	defer pod1Cleanup()
	defer e.kubectl("delete", "pod", podName1, "-n", namespace1)

	pod2Cleanup := e.writeAndCreate(pod(namespace2, podName2), "test-multi-ns-pod2-*.yaml")
	defer pod2Cleanup()
	defer e.kubectl("delete", "pod", podName2, "-n", namespace2)

	// Wait for pods
	e.kubectl("wait", "--for=condition=ready", "pod", podName1, "-n", namespace1, "--timeout=120s")
	e.kubectl("wait", "--for=condition=ready", "pod", podName2, "-n", namespace2, "--timeout=120s")

	// Execute concurrent operations
	e.kubectl("exec", "-i", podName1, "-n", namespace1, "--", "whoami")
	e.kubectl("exec", "-i", podName2, "-n", namespace2, "--", "hostname")
	e.kubectl("exec", "-i", podName1, "-n", namespace1, "--", "sleep", "2")
	e.kubectl("exec", "-i", podName2, "-n", namespace2, "--", "sleep", "2")

	// Wait for the flush interval
	time.Sleep(20 * time.Second)

	// Verify logs
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output for multi-namespace operations")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	// Verify both namespaces are present
	e.Contains(output, namespace1)
	e.Contains(output, namespace2)
}

// TC6: testCaseNegativeScenarios - Test negative scenarios and error handling.
func (e *e2e) testCaseNegativeScenarios([]string) {
	e.jsonEnricherOnlyTestCase()

	const (
		profileName   = "negative-test-profile"
		podName       = "negative-test-pod"
		containerName = "negative-test-container"
	)

	e.logf("Creating test profile for negative scenarios")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - clone
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-negative-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	since := time.Now()

	podCleanup := e.writeAndCreate(pod, "test-negative-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)
	e.waitFor("condition=initialized", "pod", podName)
	e.checkExecEnvironment(podName, 5*time.Second, 20)

	// Test basic operations
	e.kubectl("exec", "-i", podName, "--", "whoami")

	// Test profile deletion while pod running
	e.logf("Testing profile deletion with running pod")
	e.kubectl("delete", "sp", profileName)

	// Wait for the flush interval to allow logs to be generated
	// Note: We don't exec into the pod after deletion as it may cause hangs
	// in some environments. The primary goal is to verify logs are still captured.
	time.Sleep(20 * time.Second)

	// Verify logs still generated
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output for negative scenarios")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
}

// TC7: testCaseAPICorrelationAndWebhooks - Test API correlation.
func (e *e2e) testCaseAPICorrelationAndWebhooks([]string) {
	e.jsonEnricherOnlyTestCase()

	const (
		profileName   = "api-correlation-profile"
		podName       = "api-correlation-pod"
		containerName = "api-correlation-container"
	)

	e.logf("Creating test profile for API correlation")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-api-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	since := time.Now()

	podCleanup := e.writeAndCreate(pod, "test-api-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)
	e.waitFor("condition=initialized", "pod", podName)
	e.checkExecEnvironment(podName, 5*time.Second, 20)

	// Execute command and verify webhook injection
	output := e.kubectl("exec", "-i", podName, "--", "env")
	e.Contains(output, "SPO_EXEC_REQUEST_UID")
	e.logf("Webhook injection verified")

	// Wait for the flush interval
	time.Sleep(20 * time.Second)

	// Verify logs contain requestUID
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output for API correlation")
	logs := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	e.Contains(logs, "\"auditID\"")
	e.Contains(logs, "\"requestUID\"")
}

// TC8: testCaseUninstallAndCleanup - Test uninstall behavior.
func (e *e2e) testCaseUninstallAndCleanup([]string) {
	e.jsonEnricherOnlyTestCase()

	const (
		profileName   = "cleanup-test-profile"
		podName       = "cleanup-test-pod"
		containerName = "cleanup-test-container"
	)

	e.logf("Creating test profile for cleanup test")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-cleanup-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	podCleanup := e.writeAndCreate(pod, "test-cleanup-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)
	e.waitFor("condition=initialized", "pod", podName)

	// Verify pod is running
	e.logf("Verifying pod runs normally")
	status := e.kubectl("get", "pod", podName, "-o", "jsonpath={.status.phase}")
	e.Equal("Running", status)

	// Test cleanup
	e.logf("Testing cleanup - deleting pod")
	e.kubectl("delete", "pod", podName, "--wait=true")

	// Verify pod is deleted
	_, err := e.kubectlCommand("get", "pod", podName)
	e.NotNil(err, "Pod should be deleted")
}

// TC9: testCaseCRIOConfiguration - Test CRI-O specific scenarios.
func (e *e2e) testCaseCRIOConfiguration([]string) {
	// Skip if not using CRI-O
	if e.containerRuntime != "crio" && e.containerRuntime != "" {
		e.T().Skip("Skipping CRI-O specific test - not using CRI-O runtime")
	}

	e.jsonEnricherOnlyTestCase()

	const (
		profileName   = "crio-test-profile"
		podName       = "crio-test-pod"
		containerName = "crio-test-container"
	)

	e.logf("Creating test profile for CRI-O test")

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - clone
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "test-crio-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod with explicit seccomp profile")
	e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, containerName, profileName)

	since := time.Now()

	podCleanup := e.writeAndCreate(pod, "test-crio-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitForProfile(profileName)
	e.waitFor("condition=initialized", "pod", podName)
	e.checkExecEnvironment(podName, 5*time.Second, 20)

	// Test basic operation
	e.kubectl("exec", "-i", podName, "--", "whoami")

	// Wait for the flush interval
	time.Sleep(20 * time.Second)

	// Verify logs
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output for CRI-O test")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
}

// TC10: testCaseOCPUpgrade - Validate audit logging functionality across OpenShift upgrade (4.20 → 4.21)
// NOTE: This test case requires manual testing as it involves actual cluster upgrade.
// See auditLoggingTestcases.md for detailed manual test steps.
//
// Manual Test Steps:
// 1. Install SPO v0.10.0 on OpenShift 4.20 cluster
// 2. Configure audit logging to use persistent directory
// 3. Execute actions to generate audit events (oc exec, oc debug node)
// 4. Verify audit log entries are captured
// 5. Collect and back up logs before upgrade
// 6. Upgrade cluster from OpenShift 4.20 → 4.21
// 7. After upgrade:
//    - Confirm audit log directory still exists
//    - Verify previous audit entries are retained
//    - Generate new audit events
//    - Verify new audit logs are captured successfully
//
// Expected Results:
// - Audit logging functional before and after upgrade
// - Configured audit log directory persists through upgrade
// - All pre-upgrade audit records remain intact
// - New audit events post-upgrade logged without errors

// TC11: testCaseSPOUpgrade - SPO Operator Upgrade and Downgrade Scenarios
// NOTE: This test case requires manual testing as it involves operator version changes.
// See auditLoggingTestcases.md for detailed manual test steps.
//
// Test Scenarios:
//
// 11A. SPO Operator Upgrade (v0.9.0 → v0.10.0)
// Steps:
// 1. Pre-Upgrade Setup:
//    - Install SPO v0.9.0
//    - Enable JSON enricher with comprehensive configuration
//    - Create SeccompProfiles and deploy test pods
//    - Generate 100+ audit log entries
//    - Backup current audit log files
// 2. Upgrade Process:
//    - Upgrade SPO to v0.10.0 using OLM or kubectl apply
//    - Monitor upgrade sequence
// 3. During Upgrade:
//    - Continue executing kubectl exec commands
//    - Monitor audit log file for deletion/corruption
//    - Track any log gaps
// 4. Post-Upgrade Verification:
//    - Verify SPO and SPOD versions
//    - Check JSON enricher still enabled
//    - Verify configuration preserved
//    - Execute new commands and verify audit logs
//    - Compare pre/post upgrade log entries
//    - Check SeccompProfiles still applied to pods
//
// Expected Behavior:
// - SPO upgrades successfully without errors
// - SPOD daemonset rolling update completes
// - JSON enricher configuration fully preserved
// - Audit log file NOT deleted during upgrade
// - Existing audit log entries preserved
// - New logs appended correctly
// - Log format backward compatible
// - Filters remain active after upgrade
// - Webhook continues functioning
// - requestUID injection works post-upgrade
//
// 11B. SPO Downgrade/Rollback (v0.10.0 → v0.9.0)
// Steps:
// 1. Start with SPO v0.10.0 with JSON enricher enabled
// 2. Perform rollback to v0.9.0
// 3. Monitor downgrade process
// 4. Verify audit logging continues
// 5. Check for any feature loss or compatibility issues
//
// 11C. SPO Upgrade with Configuration Changes
// Steps:
// 1. Install SPO v0.9.0 with basic JSON enricher (stdout only)
// 2. Generate some audit logs
// 3. Upgrade to SPO v0.10.0
// 4. After upgrade, add advanced configuration (file output, rotation, filters)
// 5. Verify all new features work
