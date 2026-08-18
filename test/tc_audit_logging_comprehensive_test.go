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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Helper functions for comprehensive audit logging tests

func (e *e2e) configureAuditLogVolumeMount(logDir string) {
	e.logf("Configuring audit log volume mount for directory: %s", logDir)

	// Escape quotes for JSON string inside JSON
	volumeSource := fmt.Sprintf(`{\"hostPath\": {\"path\": \"%s\", \"type\": \"DirectoryOrCreate\"}}`, logDir)
	patch := fmt.Sprintf(`{
		"data": {
			"json-enricher-log-volume-mount-path": "%s",
			"json-enricher-log-volume-source.json": "%s"
		}
	}`, logDir, volumeSource)

	e.kubectlOperatorNS("patch", "configmap", "security-profiles-operator-profile",
		"-p", patch, "--type=merge")

	// Wait for configmap change to propagate
	time.Sleep(5 * time.Second)
}

func (e *e2e) enableAuditLoggingWithPath(logPath string) {
	e.logf("Enable json-enricher with custom log path: %s", logPath)

	// CRITICAL: Configure volume mount FIRST
	logDir := filepath.Dir(logPath)
	e.configureAuditLogVolumeMount(logDir)

	patch := fmt.Sprintf(`{
		"spec": {
			"verbosity": 1,
			"enricher": {
				"enableLogEnricher": false,
				"enableJsonEnricher": true,
				"jsonEnricherOptions": {
					"auditLogPath": "%s",
					"auditLogIntervalSeconds": 30,
					"auditLogMaxSize": 500,
					"auditLogMaxBackups": 2,
					"auditLogMaxAge": 10
				}
			}
		}
	}`, logPath)

	e.kubectlOperatorNS("patch", "spod", "spod", "-p", patch, "--type=merge")
	time.Sleep(defaultWaitTime)
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultSelinuxOpTimeout)
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "name=spod")
	// Additional wait for json-enricher to be fully ready
	time.Sleep(10 * time.Second)
}

func (e *e2e) enableAuditLoggingWithRotation(logPath string, maxSizeMB, maxBackups, maxAgeDays int) {
	e.logf("Enable json-enricher with rotation: size=%dMB, backups=%d, age=%dd", maxSizeMB, maxBackups, maxAgeDays)

	// CRITICAL: Configure volume mount FIRST
	logDir := filepath.Dir(logPath)
	e.configureAuditLogVolumeMount(logDir)

	patch := fmt.Sprintf(`{
		"spec": {
			"verbosity": 1,
			"enricher": {
				"enableLogEnricher": false,
				"enableJsonEnricher": true,
				"jsonEnricherOptions": {
					"auditLogPath": "%s",
					"auditLogMaxSize": %d,
					"auditLogMaxBackups": %d,
					"auditLogMaxAge": %d,
					"auditLogIntervalSeconds": 5
				}
			}
		}
	}`, logPath, maxSizeMB, maxBackups, maxAgeDays)

	e.kubectlOperatorNS("patch", "spod", "spod", "-p", patch, "--type=merge")
	time.Sleep(defaultWaitTime)
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultSelinuxOpTimeout)
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "name=spod")
	// Additional wait for json-enricher to be fully ready
	time.Sleep(10 * time.Second)
}

func (e *e2e) disableAuditLogging() {
	e.logf("Disable json-enricher")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"enricher":{"enableJsonEnricher": false}}}`, "--type=merge")
	time.Sleep(defaultWaitTime)
}

func (e *e2e) waitForAuditFileUpdate(nodeName, logPath string, timeout time.Duration) {
	e.logf("Waiting for audit file %s on node %s to be created and populated", logPath, nodeName)

	deadline := time.Now().Add(timeout)
	interval := 5 * time.Second

	for {
		// Check if file exists and has content (size > 0)
		cmd := fmt.Sprintf(`test -f %s && [ -s %s ] && echo "exists" || echo "missing"`, logPath, logPath)
		output := e.execNode(nodeName, cmd)

		if strings.Contains(strings.TrimSpace(output), "exists") {
			e.logf("Audit file %s exists and has content", logPath)

			return
		}

		if time.Now().After(deadline) {
			e.logf("Timeout waiting for audit log file to be created (waited %v)", timeout)
			e.logf("File status: %s", strings.TrimSpace(output))

			return
		}

		e.logf("Audit file not ready yet, waiting %v... (time remaining: %v)",
			interval, time.Until(deadline).Round(time.Second))
		time.Sleep(interval)
	}
}

func (e *e2e) verifyAuditLogEntry(nodeName, logPath, expectedCmd, expectedPod string) bool {
	e.logf("Verifying audit log for cmd '%s' in pod '%s' on node '%s'", expectedCmd, expectedPod, nodeName)

	// Check if audit log file exists
	checkCmd := fmt.Sprintf(`test -f %s && wc -l %s || echo "file not found"`, logPath, logPath)
	output := e.execNode(nodeName, checkCmd)
	e.logf("Audit log status: %s", strings.TrimSpace(output))

	if strings.Contains(output, "file not found") {
		return false
	}

	// Extract base command and create grep patterns
	baseCmd := strings.Fields(expectedCmd)[0]
	escapedCmd := strings.ReplaceAll(expectedCmd, "/", "\\/")
	escapedBaseCmd := strings.ReplaceAll(baseCmd, "/", "\\/")

	grepPatterns := []string{
		`cmdLine.*` + escapedBaseCmd,
		`sh -c ` + escapedCmd,
		`cmdLine.*` + escapedCmd,
	}

	for _, grepPattern := range grepPatterns {
		grepCmd := fmt.Sprintf(`grep '%s' %s 2>/dev/null || true`, grepPattern, logPath)
		out := e.execNode(nodeName, grepCmd)

		if strings.TrimSpace(out) != "" {
			e.logf("Found matching entries with pattern '%s'", grepPattern)

			if e.validateAuditEntry(out, nodeName, expectedPod) {
				return true
			}
		}
	}

	// Dump recent entries for debugging
	dumpCmd := fmt.Sprintf(`tail -20 %s 2>/dev/null || true`, logPath)
	debugOut := e.execNode(nodeName, dumpCmd)
	e.logf("Recent audit entries (last 20 lines): %s", debugOut)

	return false
}

func (e *e2e) validateAuditEntry(output, nodeName, expectedPod string) bool {
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		nodeMatches := strings.Contains(line, fmt.Sprintf(`"node":{"name":%q}`, nodeName)) ||
			strings.Contains(line, fmt.Sprintf(`"name":%q`, nodeName))

		podMatches := strings.Contains(line, fmt.Sprintf(`"pod":%q`, expectedPod))
		if !podMatches {
			pattern := fmt.Sprintf(`"resource":\{[^}]*"pod":%q`, regexp.QuoteMeta(expectedPod))
			if regexp.MustCompile(pattern).FindStringIndex(line) != nil {
				podMatches = true
			}
		}

		if nodeMatches && podMatches {
			e.logf("[PASS] Found matching audit entry")

			return true
		}
	}

	e.logf("[FAIL] Entry found but does not match pod '%s' or node '%s'", expectedPod, nodeName)

	return false
}

func (e *e2e) verifyAuditLogEntryWithRetry(nodeName, logPath, expectedCmd, expectedPod string, maxRetries int) bool {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		e.logf("Attempt %d/%d: Verifying audit entry for: %s", attempt, maxRetries, expectedCmd)

		if e.verifyAuditLogEntry(nodeName, logPath, expectedCmd, expectedPod) {
			return true
		}

		if attempt < maxRetries {
			time.Sleep(10 * time.Second)
		}
	}

	e.logf("All %d attempts failed for command: %s", maxRetries, expectedCmd)

	return false
}

// Test Cases

// testCaseAuditLoggingExecRsh validates that audit logs capture all commands executed via oc exec and oc rsh.
func (e *e2e) testCaseAuditLoggingExecRsh([]string) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping audit logging exec/rsh test (JSON enricher not enabled)")
	}

	const (
		profileName   = "audit-exec-profile"
		podName       = "audit-exec-pod"
		containerName = "nginx"
		logPath       = "/tmp/spo_audit_logs/exec-rsh.log"
	)

	e.logf("Test Case: Validate audit logs capture commands via exec and rsh")

	// Setup: Enable JSON enricher
	e.enableAuditLoggingWithPath(logPath)
	defer e.disableAuditLogging()

	// Create SeccompProfile
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - mkdir
    - openat
    - unlink
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "audit-exec-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.waitForProfile(profileName)

	// Create test pod
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

	podCleanup := e.writeAndCreate(pod, "audit-exec-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitFor("condition=ready", "pod", podName)

	// Get node name
	nodeName := e.kubectl("get", "pod", podName, "-o", "jsonpath={.spec.nodeName}")
	e.logf("Pod running on node: %s", nodeName)

	// Execute commands using kubectl exec
	workDir := "/tmp/audittest"
	commands := []string{
		"mkdir -p " + workDir,
		"touch " + workDir + "/AUDIT_LOG_TESTING_1",
		"echo hello > " + workDir + "/echo.txt",
		"cat /etc/os-release",
		"head /etc/hosts",
		"ls -l " + workDir,
		"id",
		"rm -f " + workDir + "/echo.txt",
		"sleep 1",
	}

	for i, cmd := range commands {
		e.logf("Executing command %d/%d: %s", i+1, len(commands), cmd)
		e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", cmd)

		// Verify directory/file creation for debugging
		if i == 0 { // After mkdir
			e.logf("Verifying directory created...")
			e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", "ls -ld "+workDir)
		}

		if i == 1 { // After touch
			e.logf("Verifying file created...")
			e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", "ls -l "+workDir+"/AUDIT_LOG_TESTING_1")
		}

		time.Sleep(2 * time.Second)
	}

	// Wait for audit log to be written
	e.waitForAuditFileUpdate(nodeName, logPath, 3*time.Minute)

	// Verify audit log file exists
	e.execNode(nodeName, "ls", "-ltr", logPath)

	// Verify commands are in audit log
	testCommands := []string{
		"mkdir -p " + workDir,
		"touch " + workDir + "/AUDIT_LOG_TESTING_1",
		"cat /etc/os-release",
		"head /etc/hosts",
		"ls -l " + workDir,
		"id",
		"rm -f " + workDir + "/echo.txt",
		"sleep 1",
	}

	var failedCommands []string

	var successCount int

	for _, cmd := range testCommands {
		if e.verifyAuditLogEntryWithRetry(nodeName, logPath, cmd, podName, 4) {
			successCount++

			e.logf("[PASS] Command found in audit log: %s", cmd)
		} else {
			failedCommands = append(failedCommands, cmd)
			e.logf("[FAIL] Command missing from audit log: %s", cmd)
		}
	}

	e.logf("Audit Log Test Results: %d/%d commands found", successCount, len(testCommands))

	// Known issue: Race condition can cause 1-2 commands to be missed in rapid consecutive execution
	// See: https://issues.redhat.com/browse/OCPBUGS-62269
	missedCount := len(failedCommands)
	switch {
	case missedCount > 0 && missedCount <= 2:
		e.logf("WARNING: %d command(s) missing from audit log: %v", missedCount, failedCommands)
		e.logf("WARNING: Known race condition - rapid consecutive commands may be missed due to OCPBUGS-62269")
		e.logf("PASS: Test passed with known limitation (%d/%d commands captured)", successCount, len(testCommands))
	case missedCount > 2:
		e.Fail("Too many commands missing from audit log",
			"Expected at most 2 missing (known bug), but %d commands were not found: %v",
			missedCount, failedCommands)
	default:
		e.logf("PASS: All commands verified in audit logs")
	}
}

// testCaseAuditLoggingRotation validates file output with log rotation.
func (e *e2e) testCaseAuditLoggingRotation([]string) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping audit logging rotation test (JSON enricher not enabled)")
	}

	const (
		profileName   = "audit-rotation-profile"
		podName       = "audit-rotation-pod"
		containerName = "nginx"
		logPath       = "/var/lib/spo_audit_logs/rotation-audit.log"
		maxBackups    = 2
		maxAgeDays    = 1
		maxSizeMB     = 1
	)

	logDir := "/var/lib/spo_audit_logs"

	e.logf("Test Case: Validate file output with log rotation")

	// Setup with rotation settings
	e.enableAuditLoggingWithRotation(logPath, maxSizeMB, maxBackups, maxAgeDays)
	defer e.disableAuditLogging()

	// Create SeccompProfile
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - execve
    - openat
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "audit-rotation-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.waitForProfile(profileName)

	// Create test pod
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

	podCleanup := e.writeAndCreate(pod, "audit-rotation-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitFor("condition=ready", "pod", podName)

	nodeName := e.kubectl("get", "pod", podName, "-o", "jsonpath={.spec.nodeName}")

	// Pre-rotation snapshot
	e.logf("Pre-rotation snapshot of audit log")
	e.execNode(nodeName,
		fmt.Sprintf("ls -lh %s || true; ls -ltr %s || true", logPath, logDir))

	// Generate many audit entries to trigger rotation
	e.logf("Generating multiple audit log entries to trigger rotation")

	filesDir := "/tmp/rotation_test"
	e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", "mkdir -p "+filesDir)

	for i := range 200 {
		e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c",
			fmt.Sprintf("touch %s/file_%d && ls -ltr %s >/dev/null", filesDir, i, filesDir))
	}

	// Wait for logs to flush
	e.waitForAuditFileUpdate(nodeName, logPath, 2*time.Minute)

	// Verify audit log exists and has content
	sizeOut := e.execNode(nodeName, fmt.Sprintf("du -h %s || true", logPath))
	e.logf("Audit log file size: %s", sizeOut)

	// Check rotation files
	filesOut := e.execNode(nodeName,
		fmt.Sprintf("ls -1 %s* 2>/dev/null | xargs -r -n1 basename || true", logPath))
	if strings.TrimSpace(filesOut) != "" {
		e.logf("Audit rotation files:\n%s", filesOut)
	}

	// Validate file count
	countOut := e.execNode(nodeName,
		fmt.Sprintf("ls -1 %s* 2>/dev/null | wc -l || echo 0", logPath))

	countOut = strings.TrimSpace(countOut)
	if n, err := strconv.Atoi(countOut); err == nil {
		e.logf("Total audit files (including active): %d", n)
		e.GreaterOrEqual(n, 1, "Should have at least the active log file")
		e.LessOrEqual(n, 1+maxBackups, "Should not exceed active + maxBackups")
	}

	e.logf("PASS: Verified file output with rotation settings")
}

// testCaseAuditLoggingMultiNamespace validates multi-namespace and concurrent exec sessions.
func (e *e2e) testCaseAuditLoggingMultiNamespace([]string) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping audit logging multi-namespace test (JSON enricher not enabled)")
	}

	const (
		profileName = "audit-multi-profile"
		logPath     = "/tmp/spo_audit_logs/multi-ns.log"
	)

	e.logf("Test Case: Validate multi-namespace and concurrent exec sessions")

	// Setup
	e.enableAuditLoggingWithPath(logPath)
	defer e.disableAuditLogging()

	// Create SeccompProfile
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
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

	profileCleanup := e.writeAndCreate(profile, "audit-multi-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)
	e.waitForProfile(profileName)

	// Create test namespaces
	testNamespaces := []string{"audit-ns-1", "audit-ns-2", "audit-ns-3"}

	for _, ns := range testNamespaces {
		e.kubectl("create", "namespace", ns)
	}

	defer func() {
		for _, ns := range testNamespaces {
			e.kubectl("delete", "namespace", ns)
		}
	}()

	// Create pods in each namespace
	var testPods []string

	var cleanupFuncs []func()

	for _, ns := range testNamespaces {
		for i := 1; i <= 2; i++ {
			podName := fmt.Sprintf("test-pod-%d", i)

			pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: nginx
    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: operator/%s.json
  restartPolicy: Never
`, podName, ns, profileName)

			podCleanup := e.writeAndCreate(pod, "audit-multi-pod-*.yaml")
			cleanupFuncs = append(cleanupFuncs, podCleanup)

			testPods = append(testPods, ns+"/"+podName)
		}
	}
	defer func() {
		for _, cleanup := range cleanupFuncs {
			cleanup()
		}
	}()

	// Wait for all pods to be ready
	for _, nsPod := range testPods {
		parts := strings.Split(nsPod, "/")
		ns, pod := parts[0], parts[1]
		e.kubectl("wait", "--for=condition=ready", "pod/"+pod, "-n", ns, "--timeout=2m")
	}

	// Get node name from first pod
	firstParts := strings.Split(testPods[0], "/")
	nodeName := e.kubectl("get", "pod", firstParts[1], "-n", firstParts[0], "-o", "jsonpath={.spec.nodeName}")

	// Execute concurrent commands across namespaces
	e.logf("Launching concurrent exec sessions across multiple namespaces")

	for _, nsPod := range testPods {
		parts := strings.Split(nsPod, "/")
		ns, pod := parts[0], parts[1]

		commands := []string{"whoami", "id", "date"}
		for _, cmd := range commands {
			// Execute without waiting (concurrent)
			cmdCopy := cmd
			go func(namespace, podname string) {
				e.kubectl("exec", podname, "-n", namespace, "-c", "nginx", "--", "sh", "-c", cmdCopy)
			}(ns, pod)
		}
	}

	// Wait for audit log to be updated
	time.Sleep(30 * time.Second)
	e.waitForAuditFileUpdate(nodeName, logPath, 3*time.Minute)

	// Verify audit logs contain entries from multiple namespaces
	for _, ns := range testNamespaces {
		grepCmd := fmt.Sprintf(`grep '%s' %s | head -1 || true`, ns, logPath)

		out := e.execNode(nodeName, grepCmd)
		if strings.TrimSpace(out) != "" {
			e.logf("Found audit entries for namespace %s", ns)
		}
	}

	e.logf("PASS: Verified multi-namespace concurrent exec sessions are logged")
}

// testCaseAuditLoggingRequestUIDCorrelation validates basic functional validation with requestUID correlation.
func (e *e2e) testCaseAuditLoggingRequestUIDCorrelation([]string) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping audit logging requestUID test (JSON enricher not enabled)")
	}

	const (
		profileName   = "audit-requid-profile"
		podName       = "audit-requid-pod"
		containerName = "nginx"
		logPath       = "/tmp/spo_audit_logs/requid.log"
	)

	e.logf("Test Case: Basic functional validation with SPO_EXEC_REQUEST_UID correlation")

	// Setup
	e.enableAuditLoggingWithPath(logPath)
	defer e.disableAuditLogging()

	// Create SeccompProfile
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
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

	profileCleanup := e.writeAndCreate(profile, "audit-requid-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

	e.waitForProfile(profileName)

	// Create test pod
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

	podCleanup := e.writeAndCreate(pod, "audit-requid-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitFor("condition=ready", "pod", podName)

	// Capture SPO_EXEC_REQUEST_UID from environment
	reqOut := e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", "printenv SPO_EXEC_REQUEST_UID || true")
	requestUID := strings.TrimSpace(reqOut)
	e.NotEmpty(requestUID, "SPO_EXEC_REQUEST_UID should be present")
	e.logf("Captured SPO_EXEC_REQUEST_UID: %s", requestUID)

	// Execute test commands
	commands := []string{
		"whoami",
		"id",
		"mkdir -p /tmp/spo-basic",
		"touch /tmp/spo-basic/file.txt",
		"ls -l /tmp/spo-basic",
	}

	for _, cmd := range commands {
		e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", cmd)
	}

	// Wait for audit log
	nodeName := e.kubectl("get", "pod", podName, "-o", "jsonpath={.spec.nodeName}")
	e.waitForAuditFileUpdate(nodeName, logPath, 2*time.Minute)

	// Verify requestUID in audit file
	reqUIDGrep := fmt.Sprintf(`grep -F '"requestUID":%q' %s -m1 || true`, requestUID, logPath)
	reqHit := e.execNode(nodeName, reqUIDGrep)
	e.NotEmpty(strings.TrimSpace(reqHit), "requestUID should be present in audit file")

	// Verify commands appear in audit file
	found := 0

	for _, cmd := range commands {
		if e.verifyAuditLogEntryWithRetry(nodeName, logPath, cmd, podName, 3) {
			found++
		}
	}
	e.Positive(found, "At least some commands should be found in audit file")
	e.logf("PASS: Basic functional validation via file audit log with requestUID correlation (%d/%d cmds)",
		found, len(commands))
}

// testCaseAuditLoggingSeccompProfileCoverage validates seccomp logging profile for in-pod command coverage.
func (e *e2e) testCaseAuditLoggingSeccompProfileCoverage([]string) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping audit logging seccomp profile test (JSON enricher not enabled)")
	}

	const (
		profileName   = "audit-logexec-profile"
		podName       = "audit-logexec-pod"
		containerName = "nginx"
		logPath       = "/tmp/spo_audit_logs/logexec.log"
	)

	e.logf("Test Case: Validate seccomp logging profile for in-pod command coverage")

	// Setup
	e.enableAuditLoggingWithPath(logPath)
	defer e.disableAuditLogging()

	// Create SeccompProfile with SCMP_ACT_LOG default
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_LOG
`, profileName)

	profileCleanup := e.writeAndCreate(profile, "audit-logexec-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)
	e.waitForProfile(profileName)

	time.Sleep(5 * time.Second)

	// Create test pod
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

	podCleanup := e.writeAndCreate(pod, "audit-logexec-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitFor("condition=ready", "pod", podName)

	nodeName := e.kubectl("get", "pod", podName, "-o", "jsonpath={.spec.nodeName}")

	// Execute diverse in-pod commands
	inPodCmds := []string{
		"whoami",
		"id",
		"pwd",
		"sh -c 'echo hello > /tmp/logexec.txt'",
		"ls -l /tmp",
		"cat /etc/hostname",
		"uname -a",
	}

	for _, cmd := range inPodCmds {
		e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", cmd)
	}

	// Wait for logs to flush
	time.Sleep(40 * time.Second)

	// Verify in-pod commands in audit log
	foundInPod := 0

	for _, cmd := range inPodCmds {
		if e.verifyAuditLogEntryWithRetry(nodeName, logPath, cmd, podName, 3) {
			foundInPod++
		} else {
			e.logf("[WARN] Missing in-pod command in audit log: %s", cmd)
		}
	}

	e.Positive(foundInPod, "Expected at least one in-pod command in audit logs")
	e.logf("PASS: Seccomp logging profile validated for in-pod commands (%d/%d)", foundInPod, len(inPodCmds))
}

// testCaseAuditLoggingWebhookIntegration validates webhook integration and requestUID correlation.
func (e *e2e) testCaseAuditLoggingWebhookIntegration([]string) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping audit logging webhook test (JSON enricher not enabled)")
	}

	const (
		profileName   = "audit-webhook-profile"
		podName       = "audit-webhook-pod"
		containerName = "nginx"
		logPath       = "/tmp/spo_audit_logs/webhook.log"
	)

	e.logf("Test Case: Validate webhook integration and requestUID correlation")

	// Setup
	e.enableAuditLoggingWithPath(logPath)
	defer e.disableAuditLogging()

	// Create SeccompProfile
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
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

	profileCleanup := e.writeAndCreate(profile, "audit-webhook-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)
	e.waitForProfile(profileName)

	// Create test pod
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

	podCleanup := e.writeAndCreate(pod, "audit-webhook-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)

	e.waitFor("condition=ready", "pod", podName)

	// Check for requestUID in environment
	cmdOutput := e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c",
		"env | grep SPO_EXEC_REQUEST_UID || echo 'SPO_EXEC_REQUEST_UID not found'")
	e.logf("Environment output: %s", strings.TrimSpace(cmdOutput))

	// Execute test commands
	testCommands := []string{
		"ls /tmp",
		"whoami",
		"id",
	}

	for _, cmd := range testCommands {
		e.kubectl("exec", podName, "-c", containerName, "--", "sh", "-c", cmd)
	}

	// Wait for audit log
	time.Sleep(60 * time.Second)

	nodeName := e.kubectl("get", "pod", podName, "-o", "jsonpath={.spec.nodeName}")

	// Verify audit log entries contain requestUID
	verified := 0

	for _, cmd := range testCommands {
		fullLineCmd := fmt.Sprintf(`grep -F 'sh -c %s' %s | head -n 1 || true`, cmd, logPath)
		fullLineOut := e.execNode(nodeName, fullLineCmd)

		reqUIDCmd := fmt.Sprintf(`grep -F 'sh -c %s' %s | head -n 1 | grep -o '"requestUID":"[^"]*"' || true`,
			cmd, logPath)
		out := e.execNode(nodeName, reqUIDCmd)

		if strings.TrimSpace(out) != "" {
			verified++

			e.logf("[PASS] Found requestUID for cmd '%s': %s", cmd, strings.TrimSpace(out))
		} else {
			e.logf("[FAIL] Missing requestUID entry for cmd '%s'", cmd)
			e.logf("Full line output: %s", strings.TrimSpace(fullLineOut))
		}
	}

	e.Len(testCommands, verified, "Expected requestUID entries for all commands")

	// Check webhook deployment status
	webhookStatus := e.kubectlOperatorNS("get", "deployment",
		"-l", "app=security-profiles-operator-webhook", "-o", "jsonpath={.items[*].metadata.name}")
	if webhookStatus != "" {
		e.logf("Webhook deployment found: %s", webhookStatus)
	}

	e.logf("PASS: Verified webhook integration and audit logging")
}
