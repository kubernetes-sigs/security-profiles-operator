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
	e.jsonEnricherOnlyTestCaseFileOptions(jsonLogFileName)

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

	const maximum = 20
	for i := 0; i <= maximum; i++ {
		output := e.kubectl("get", "pod", podName)
		if strings.Contains(output, "Running") {
			break
		}

		if i == maximum {
			e.Fail("Unable to get pod in running state")
		}

		time.Sleep(5 * time.Second)
	}

	time.Sleep(5 * time.Second)

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

	const maximum = 20
	for i := 0; i <= maximum; i++ {
		output := e.kubectl("get", "pod", podName)
		if strings.Contains(output, "Running") {
			break
		}

		if i == maximum {
			e.Fail("Unable to get pod in running state")
		}

		time.Sleep(5 * time.Second)
	}

	time.Sleep(10 * time.Second)

	e.kubectl("exec", "-it", podName, "--", "sleep", "5")
	envOutput := e.kubectl("exec", "-it", podName, "--", "env")
	e.Contains(envOutput, "SPO_EXEC_REQUEST_UID")

	// wait for at least one component of the expected logs to appear
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(`(?m)"requestUID"`))

	e.logf("Wait for the audit lines to come within 30 seconds")
	time.Sleep(30 * time.Second)
	e.logf("Checking JSON enricher output")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "json-enricher")

	// then match the rest
	e.Contains(output, "\"auditID\"")
	e.Contains(output, "\"requestUID\"")
	e.Contains(output, "\"cmdLine\"")
	e.Contains(output, "sleep")
	e.Contains(output, "\"container\"")
	e.Contains(output, "\"namespace\"")
}
