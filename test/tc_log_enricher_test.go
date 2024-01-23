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

func (e *e2e) testCaseLogEnricher([]string) {
	e.logEnricherOnlyTestCase()

	const (
		profileName   = "enricherprofile"
		podName       = "enricherpod"
		containerName = "enrichercontainer"
	)

	e.logf("Creating test profile")
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
`, profileName)
	profileCleanup := e.writeAndCreate(profile, "test-profile-*.yaml")
	defer profileCleanup()
	defer e.kubectl("delete", "sp", profileName)

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
      localhostProfile: operator/%s/%s.json
  restartPolicy: Never
`, podName, containerName, namespace, profileName)

	since := time.Now()
	podCleanup := e.writeAndCreate(pod, "test-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)
	e.waitForProfile(profileName)

	e.waitFor("condition=initialized", "pod", podName)
	const max = 20
	for i := 0; i <= max; i++ {
		output := e.kubectl("get", "pod", podName)
		if strings.Contains(output, "Running") {
			break
		}
		if i == max {
			e.Fail("Unable to get pod in running state")
		}
		time.Sleep(5 * time.Second)
	}

	// wait for at least one component of the expected logs to appear
	e.waitForEnricherLogs(since, regexp.MustCompile(`(?m)"syscallName"="listen"`))

	e.logf("Checking log enricher output")
	output := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "log-enricher")

	// then match the rest
	e.Contains(output, `"audit"`)
	e.Contains(output, `type="seccomp"`)
	e.Contains(output, `executable="/usr/sbin/nginx"`)
	e.Contains(output, fmt.Sprintf(`pod=%q`, podName))
	e.Contains(output, fmt.Sprintf(`container=%q`, containerName))
	e.Contains(output, fmt.Sprintf(`namespace=%q`, namespace))
	e.Regexp(`(?mU)\snode=".*"\s`, output)
	e.Contains(output, `pid`)
	e.Contains(output, `timestamp`)
	e.Contains(output, `syscallName="listen"`)
	e.Contains(output, `syscallID=50`)

	if e.singleNodeEnvironment {
		// we only run the metrics checks in a single node environment because otherwise it's a lottery
		// which spod instance do we hit and the test is not stable

		metrics := e.runAndRetryPodCMD(curlSpodCMD)
		e.Regexp(fmt.Sprintf(`(?m)security_profiles_operator_seccomp_profile_audit_total{`+
			`container="%s",`+
			`executable="/usr/sbin/nginx",`+
			`namespace="%s",`+
			`node=".*",`+
			`pod="%s",`+
			`syscall="listen"} \d+`,
			containerName, namespace, podName,
		), metrics)
	}
}
