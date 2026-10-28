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
	"regexp"
	"strings"
	"time"
)

func (e *e2e) testCaseJsonEnricherFileOptions([]string) {
	jsonLogFileName := "/tmp/json-logs/jsonEnricher.out"
	//nolint:lll  // long filter.
	e.jsonEnricherOnlyTestCaseFileOptions(
		jsonLogFileName,
		`[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]`,
	)

	const (
		profileName   = "jsonenricherprofile"
		podName       = "jsonenricherpod"
		containerName = "jsonenrichercontainer"
	)

	e.logf("Creating test profile for JSON Enricher")

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
    - listen
    - execve
    - clone
    - getpid
`, profileName)

	e.writeAndCreate(profile, "test-profile-*.yaml")
	e.kubectlCleanup("sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	// The exec metadata webhook excludes the operator namespace, so run the
	// test pod in its own namespace.
	e.logf("Creating test pod")
	defer e.switchToJsonEnricherNs()()

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

	e.writeAndCreate(pod, "test-pod-*.yaml")
	e.kubectlCleanup("pod", podName)

	e.waitForProfile(profileName)

	e.waitFor("condition=initialized", "pod", podName)

	e.checkExecEnvironment(podName, nil, execEnvironmentTimeout)

	// In 5 seconds the process info will be captured.
	e.kubectl("exec", "-i", podName, "--", "sleep", "5")

	// The polls below cover the flush interval of 20 seconds. Wait for the
	// exec record itself, since other records may be flushed before it.
	output := e.waitForJsonEnricherFileLogs(jsonLogFileName,
		regexp.MustCompile(`(?m)"requestUID"`),
		regexp.MustCompile(`"sleep"|"/"`))

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")

	// Special case in ubuntu: \"cmdLine\":\"\",\"executable\":\"/\".
	e.True(stringContainsAny(output, "\"sleep\"", "\"/\""))

	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")

	// Every record has the version which the second filter drops, so only the
	// records of execs, which the first filter keeps, reach the file.
	for line := range strings.Lines(output) {
		if strings.TrimSpace(line) == "" {
			continue
		}

		e.Contains(line, "\"requestUID\"", "record not filtered")
	}
}

// jsonEnricherTestNamespace is the namespace of the JSON enricher test pods.
const jsonEnricherTestNamespace = "spo-json-enricher-test"

// switchToJsonEnricherNs switches to the namespace of the JSON enricher test
// pods and returns the function which switches back. The namespace gets
// deleted once the current test ends, with the pods the test and its debug
// sessions created in it.
func (e *e2e) switchToJsonEnricherNs() func() {
	restoreNs := e.switchToNs(jsonEnricherTestNamespace)
	e.kubectlCleanup("namespace", jsonEnricherTestNamespace)

	return restoreNs
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
    - clone
    - fork
    - execveat
`, profileName)

	e.writeAndCreate(profile, "test-profile-*.yaml")
	e.kubectlCleanup("sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	// The exec metadata webhook excludes the operator namespace, so run the
	// test pod in its own namespace.
	e.logf("Creating test pod")
	defer e.switchToJsonEnricherNs()()

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

	e.writeAndCreate(pod, "test-pod-*.yaml")
	e.kubectlCleanup("pod", podName)

	e.waitForProfile(profileName)

	e.waitFor("condition=initialized", "pod", podName)

	e.checkExecEnvironment(podName, nil, execEnvironmentTimeout)

	// The debug session adds an ephemeral container, whose environment the
	// exec metadata webhook patches. Its sleep is not asserted below, the
	// enricher does not reliably attribute it.
	e.kubectl("debug", "--profile", "general", "-i", podName, "--image",
		busyboxImage, "--", "sleep", "6")

	// In 5 seconds the process info will be captured.
	e.kubectl("exec", "-i", podName, "-c", containerName, "--", "sleep", "5")

	// The debug pod of the node stays behind in the test namespace, which
	// gets deleted with the test.
	nodeName := e.kubectl("get", "nodes",
		"-o", "jsonpath='{.items[0].metadata.name}'")
	nodeDebuggingPodEnvOutput := e.kubectl("debug", "--profile", "general",
		"node/"+strings.Trim(nodeName, "'"), "--image", busyboxImage, "-it", "--", "env")
	e.Contains(nodeDebuggingPodEnvOutput, "SPO_EXEC_REQUEST_UID")
	e.logf("The env output has SPO_EXEC_REQUEST_UID")

	// The polls below cover the flush interval of 20 seconds. Wait for the
	// exec record itself, since other records may be flushed before it.
	// Check the matched output, a later fetch by label selector would only
	// return the last 10 lines and may miss the exec record.
	output := e.waitForJsonEnricherLogs(since,
		regexp.MustCompile(`(?m)"requestUID"`),
		regexp.MustCompile(`sleep 5`))
	e.logf("Checking JSON enricher output")

	// then match the rest
	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")
	e.Contains(output, "sleep 5")
	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")
}

// Checks exec environment for the pod.
func (e *e2e) checkExecEnvironment(
	podName string,
	namespace *string,
	timeout time.Duration,
) {
	if !e.podRunning(podName, namespace, timeout) {
		e.logf("Pod %s is not running", podName)
		e.Fail("Pod is not running")
	}

	if !e.canExec(podName, timeout) {
		e.logf("Pod %s cannot be exec", podName)
		e.Fail("Pod cannot be exec")
	}
}

// Attempt exec into the pod and make sure its up.
func (e *e2e) canExec(podName string, timeout time.Duration) bool {
	const expectedEnvVar = "SPO_EXEC_REQUEST_UID"

	err := poll(timeout, defaultPollInterval, func() error {
		output := e.kubectl("exec", "-i", podName, "--", "env")
		if !strings.Contains(output, expectedEnvVar) {
			return fmt.Errorf("no %s in the environment of pod %s", expectedEnvVar, podName)
		}

		return nil
	})
	if err != nil {
		e.logf("Cannot exec pod %s: %v", podName, err)

		return false
	}

	return true
}
