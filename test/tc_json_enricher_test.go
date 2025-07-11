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

	e.checkExecEnvironment(podName, "default", 5*time.Second, 20)

	e.kubectl("exec", "-it", podName, "--", "sleep", "5") // In 5 seconds the process info will be captured
	e.kubectl("exec", "-it", podName, "--", "env")

	// wait for at least one component of the expected logs to appear
	output := e.waitForJsonEnricherFileLogs(jsonLogFileName,
		regexp.MustCompile(`(?m)"requestUID"`))

	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")
	e.Contains(output, "sleep")
	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")
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

	e.checkExecEnvironment(podName, "default", 5*time.Second, 20)

	e.logf("kubectl debug and sleep for 6 seconds")
	// Command failed once in the Fedora platform.
	e.kubectl("debug", "-i", podName, "--image", "busybox:latest", "--", "sleep", "6")
	e.logf("kubectl exec and sleep for 5 seconds")
	e.kubectl("exec", "-i", podName, "--", "sleep", "5")

	nodeName := e.kubectl("get", "nodes",
		"-o", "jsonpath='{.items[0].metadata.name}'")
	e.kubectl("debug", "node/"+strings.Trim(nodeName, "'"), "--image", "busybox",
		"-it", "--", "env")
	// Uncomment after kubectl debug node label.
	// PR https://github.com/kubernetes/kubernetes/pull/131791.
	// e.Contains(nodeDebuggingPodEnvOutput, "SPO_EXEC_REQUEST_UID")
	// e.logf("The env output has SPO_EXEC_REQUEST_UID")

	// wait for at least one component of the expected logs to appear
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))
	e.logf("Checking JSON enricher output")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	// then match the rest
	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")
	// Failed once in the Fedora platform.
	e.Contains(output, "sleep 6")
	e.Contains(output, "sleep 5")
	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")
}

// Checks exec environment for the pod.
func (e *e2e) checkExecEnvironment(podName, namespace string, interval time.Duration, maxTimes int) {
	if !e.podRunning(podName, namespace, interval, maxTimes) {
		e.logf("Pod %s is not running", podName)
		e.Fail("Pod is not running")
	}

	if e.canExec(podName, 5, 5) {
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
