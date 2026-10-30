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

	e.createJsonEnricherTestPod()

	readLogs := e.jsonEnricherFileLogsReader(jsonLogFileName)

	var output string

	// Wait for the exec record itself, since other records may be flushed
	// before it.
	e.execUntilJsonEnricherRecorded(func() error {
		return poll(jsonEnricherRecordTimeout, 10*time.Second, func() error {
			e.logf("Waiting for JSON enricher to record syscalls")

			logs, err := readLogs()
			if err != nil {
				return err
			}

			output = logs

			return unmatchedLogs(logs, []*regexp.Regexp{jsonEnricherExecRecord})
		})
	})

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

// jsonEnricherExecMarker is an assignment of the env command which the JSON
// enricher test cases exec, which tells its record apart.
const jsonEnricherExecMarker = "SPO_JSON_ENRICHER_TEST=exec"

// jsonEnricherExecCommand is the command which the JSON enricher test cases
// exec, see execUntilJsonEnricherRecorded. The env command gets the request UID
// as an assignment, and runs a sleep long enough for the enricher to read the
// details of the process from /proc.
var jsonEnricherExecCommand = []string{"env", jsonEnricherExecMarker, "sleep", "7"}

// jsonEnricherExecRecord matches the record of jsonEnricherExecCommand with
// its request. The process execs twice, env and then sleep, so the record has
// the command line of env with the sleep if it got read before the second
// exec, and the one of sleep otherwise. Either has the request.
var jsonEnricherExecRecord = regexp.MustCompile(
	`"cmdLine":"(env ` + regexp.QuoteMeta(jsonEnricherExecMarker) +
		` [^"]* )?sleep 7 ?".*"requestUID":"[^"]+"`,
)

// jsonEnricherRecordTimeout is how long a record of the JSON enricher is
// waited for, which covers its flush interval of 20 seconds.
const jsonEnricherRecordTimeout = time.Minute

// execUntilJsonEnricherRecorded execs jsonEnricherExecCommand in the test
// container until poll finds its record, at most three times. The JSON
// enricher does not get the details of every process: once a process is gone
// from /proc, only the BPF process cache can tell them, which does not know
// every process on every node.
func (e *e2e) execUntilJsonEnricherRecorded(poll func() error) {
	const attempts = 3

	for attempt := 1; ; attempt++ {
		e.kubectl(append([]string{
			"exec", "-i", jsonEnricherTestPod, "-c", jsonEnricherTestContainer, "--",
		}, jsonEnricherExecCommand...)...)

		err := poll()
		if err == nil {
			return
		}

		if attempt == attempts {
			e.Failf("condition not met", "%v", err)

			return
		}

		e.logf("Running the exec again: %v", err)
	}
}

func (e *e2e) testCaseJsonEnricher([]string) {
	e.jsonEnricherOnlyTestCase()

	since := e.createJsonEnricherTestPod()

	// The debug session adds an ephemeral container, whose environment the
	// exec metadata webhook patches. Its sleep is not asserted below, the
	// enricher does not reliably attribute it.
	e.kubectl("debug", "--profile", "general", "-i", jsonEnricherTestPod, "--image",
		busyboxImage, "--", "sleep", "6")

	// The debug pod of the node stays behind in the test namespace, which
	// gets deleted with the test.
	nodeName := e.kubectl("get", "nodes",
		"-o", "jsonpath='{.items[0].metadata.name}'")
	nodeDebuggingPodEnvOutput := e.kubectl("debug", "--profile", "general",
		"node/"+strings.Trim(nodeName, "'"), "--image", busyboxImage, "-it", "--", "env")
	e.Contains(nodeDebuggingPodEnvOutput, "SPO_EXEC_REQUEST_UID")
	e.logf("The env output has SPO_EXEC_REQUEST_UID")

	// Wait for the exec record itself, with its request, since other records
	// may be flushed before it. A process which exited before its line got
	// read does not always get its container, so the container comes from
	// any record of the pod, like the ones of its entrypoint.
	conditions := []*regexp.Regexp{jsonEnricherExecRecord, regexp.MustCompile(
		`"resource":\{"container":"` + regexp.QuoteMeta(jsonEnricherTestContainer) +
			`","namespace":"` + regexp.QuoteMeta(jsonEnricherTestNamespace) + `"`,
	)}

	e.execUntilJsonEnricherRecorded(func() error {
		_, err := e.pollEnricherContainerLogs(
			jsonEnricherRecordTimeout, "json-enricher", since, conditions...,
		)

		return err
	})
}

// testCaseJsonEnricherExecCommand asserts that the JSON enricher records the
// command line and the request of an exec of a command other than env, which
// the exec metadata webhook runs through env: its process execs twice.
func (e *e2e) testCaseJsonEnricherExecCommand([]string) {
	e.jsonEnricherOnlyTestCase()

	since := e.createJsonEnricherTestPod()

	e.kubectl("exec", "-i", jsonEnricherTestPod, "-c", jsonEnricherTestContainer,
		"--", "sleep", "5")

	// The process logs two execs: the one of env, with the executable of
	// the runtime, and the one of sleep, with the one of env. The sleep
	// itself logs no syscall of the profile. The process is cached by its
	// PID and start time, which the second exec keeps, so both records get
	// the command line of env with the sleep if it got read before the
	// second exec, and the one of sleep otherwise. Either has the request.
	// The keys of a record are sorted, so its request comes right before
	// its resource. The sleep runs long enough to get its container.
	e.waitForJsonEnricherLogs(since, regexp.MustCompile(
		`"cmdLine":"(env [^"]* )?sleep 5 ?".*"requestUID":"[^"]+","resource":\{"container":"`+
			regexp.QuoteMeta(jsonEnricherTestContainer)+`","namespace":"`+
			regexp.QuoteMeta(jsonEnricherTestNamespace)+`"`,
	))
}

const (
	// jsonEnricherTestPod and jsonEnricherTestContainer run the execs of the
	// JSON enricher test cases, see createJsonEnricherTestPod.
	jsonEnricherTestPod       = "jsonenricherpod"
	jsonEnricherTestContainer = "jsonenrichercontainer"
)

// jsonEnricherExecSyscalls are the syscalls of the execs, which the JSON
// enricher test cases log.
var jsonEnricherExecSyscalls = []string{"execve", "clone", "fork", "execveat"}

// createJsonEnricherTestPod creates a profile which logs the syscalls of the
// execs, and a pod running with it in the JSON enricher test namespace, and
// waits until the pod takes execs. The exec metadata webhook excludes the
// operator namespace. The profile gets created before the test switches to
// that namespace, which the namespaced operator does not watch. The test
// switches back once it ends. It returns when the pod got created.
func (e *e2e) createJsonEnricherTestPod() (since time.Time) {
	const profileName = "jsonenricherprofile"

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
    - %s
`, profileName, strings.Join(jsonEnricherExecSyscalls, "\n    - "))

	e.writeAndCreate(profile, "test-profile-*.yaml")
	e.kubectlCleanup("sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")

	e.cleanup(e.switchToJsonEnricherNs())

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
`, jsonEnricherTestPod, jsonEnricherTestContainer, profileName)

	since = time.Now()

	e.writeAndCreate(pod, "test-pod-*.yaml")
	e.kubectlCleanup("pod", jsonEnricherTestPod)

	e.waitForProfile(profileName)

	e.waitFor("condition=initialized", "pod", jsonEnricherTestPod)

	e.checkExecEnvironment(jsonEnricherTestPod, nil, execEnvironmentTimeout)

	return since
}

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
