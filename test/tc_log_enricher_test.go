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

// testCaseLogEnricherBpf checks the BPF source of the log enricher, which
// only reports AppArmor audit events (it hooks aa_audit), with a profile
// that has no rule for the file the pod writes.
func (e *e2e) testCaseLogEnricherBpf([]string) {
	e.logEnricherBpfOnlyTestCase()

	const (
		profileName   = "enricher-apparmor"
		podName       = "enricherpod-apparmor"
		containerName = "enrichercontainer"
	)

	e.logf("Creating test AppArmor profile")

	// The profile denies the write by having no rule for it. Explicit deny
	// rules, which readOnlyPaths renders as well, are not audited, so no
	// event would reach aa_audit. The executable rules let the shell and
	// the busybox applets run, the base abstraction covers the libraries.
	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: AppArmorProfile
metadata:
  name: %s
spec:
  abstract:
    executable:
      allowedExecutables:
      - /bin/**
      - /usr/bin/**
`, profileName)

	e.writeAndCreate(profile, "test-profile-*.yaml")
	e.kubectlCleanup("apparmorprofile", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitFor("jsonpath={.status.status}=Installed", "apparmorprofile", profileName)

	e.logf("Creating test pod")
	namespace := e.getCurrentContextNamespace(defaultNamespace)

	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: busybox:latest
    name: %s
    command: ["sh", "-c", "while true; do touch /tmp/denied; sleep 1; done"]
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: %s
  restartPolicy: Never
`, podName, containerName, profileName)

	since := time.Now()

	e.writeAndCreate(pod, "test-pod-*.yaml")
	e.kubectlCleanup("pod", podName)

	e.waitFor("jsonpath={.status.phase}=Running", "pod", podName)

	e.logf("Checking log enricher output")
	e.waitForEnricherLogs(since, enricherLogLine(
		"type", "apparmor",
		"namespace", namespace,
		"pod", podName,
		"container", containerName,
		"apparmor", "DENIED",
		"name", "/tmp/denied",
	))
}

func (e *e2e) testCaseLogEnricher([]string) {
	e.logEnricherOnlyTestCase()

	const (
		profileName   = "enricherprofile"
		podName       = "enricherpod"
		containerName = "enrichercontainer"
	)

	e.logf("Creating test profile")

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
`, profileName)

	e.writeAndCreate(profile, "test-profile-*.yaml")
	e.kubectlCleanup("sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating test pod")
	namespace := e.getCurrentContextNamespace(defaultNamespace)

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

	e.waitFor("jsonpath={.status.phase}=Running", "pod", podName)

	// wait for at least one component of the expected logs to appear
	e.waitForEnricherLogs(since, enricherLogLine("syscallName", "listen"))

	e.logf("Checking log enricher output")
	output, err := e.spodContainerLogs(since, "log-enricher")
	e.Require().NoError(err)

	// then match the rest
	e.Contains(output, `"audit"`)
	e.Contains(output, `type="seccomp"`)
	e.Contains(output, `executable="/usr/sbin/nginx"`)

	indexType := strings.Index(output, `type="seccomp`)
	indexExecutable := strings.Index(output, `executable="/usr/sbin/nginx"`)

	e.Less(indexType, indexExecutable) // Test if the ordering is intact.

	e.Contains(output, fmt.Sprintf(`pod=%q`, podName))
	e.Contains(output, fmt.Sprintf(`container=%q`, containerName))
	e.Contains(output, fmt.Sprintf(`namespace=%q`, namespace))
	e.Regexp(`(?mU)\snode=".*"\s`, output)
	e.Contains(output, `pid`)
	e.Contains(output, `timestamp`)
	e.Contains(output, `syscallName="listen"`)
	e.Contains(output, `syscallID=50`)

	// The daemon of the node of the pod counts the audit lines.
	auditMetric := regexp.MustCompile(fmt.Sprintf(
		`(?m)security_profiles_operator_seccomp_profile_audit_total{`+
			`container="%s",`+
			`namespace="%s",`+
			`node=".*",`+
			`pod="%s",`+
			`syscall="listen"} \d+`,
		containerName, namespace, podName,
	))

	e.eventually(metricsTimeout, defaultPollInterval, func() error {
		return unmatchedLogs(e.scrapeSpodMetrics(), []*regexp.Regexp{auditMetric})
	})
}

func (e *e2e) testCaseLogEnricherWithFilters([]string) {
	const (
		profileName   = "enricherprofile"
		podName       = "enricherpod"
		containerName = "enrichercontainer"
	)

	e.logEnricherOnlyTestCaseWithFilters(
		fmt.Sprintf(
			`"[{\"priority\":100, \"level\":\"None\",\"matchKeys\":[\"syscallID\"],\"matchValues\":[\"%d\"]}]"`,
			50,
		),
	)

	// It runs after the JSON enricher test case, which enabled the exec
	// metadata webhook. Disabling the JSON enricher has to remove it again.
	e.waitForNoExecWebhook(podStartTimeout)

	e.logf("Creating test profile")

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

	e.logf("Creating test pod")

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

	e.waitFor("jsonpath={.status.phase}=Running", "pod", podName)

	envOutput := e.kubectl("exec", podName, "--", "env")
	e.NotContains(envOutput, "SPO_EXEC_REQUEST_UID", "exec mutated without the JSON enricher")

	// nginx calls listen after the execve of its start, so a listen line
	// may only be missing because the enricher did not process it yet. An
	// exec into the pod adds later lines, and once a getpid line shows up,
	// the check that no listen line gets logged runs for a while, which
	// covers the enricher catching up.
	e.waitForEnricherLogs(since, enricherLogLine("syscallName", "execve"))
	e.kubectl("exec", podName, "--", "sh", "-c", "exit 0")
	e.waitForEnricherLogs(since, enricherLogLine("syscallName", "getpid"))

	e.logf("Checking that the log enricher filters the listen lines")

	listenLine := fmt.Sprintf(`syscallID=%d`, 50)

	e.consistently(absentProfileTimeout, defaultPollInterval, func() error {
		output, err := e.spodContainerLogs(since, "log-enricher")
		if err != nil {
			return err
		}

		if strings.Contains(output, listenLine) {
			return fmt.Errorf("the filtered %s got logged", listenLine)
		}

		return nil
	})
}
