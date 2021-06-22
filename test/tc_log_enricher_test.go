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
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
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

	e.logf("Creating test pod")
	namespace := e.getCurrentContextNamespace(defaultNamespace)

	// Usually, the `sleep 5` is not required if the machine executing the test
	// is fast enough to extract the container ID from the cgroup wile the
	// container is still running. We still add it here for deflaking purposes.
	pod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx:1.19.1
    name: %s
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s/%s.json
  restartPolicy: Never
`, podName, containerName, namespace, profileName)

	podCleanup := e.writeAndCreate(pod, "test-pod-*.yaml")
	defer podCleanup()
	defer e.kubectl("delete", "pod", podName)
	e.waitFor("condition=ready", "sp", profileName)

	e.waitFor("condition=initialized", "pod", podName)
	for i := 0; i < 20; i++ {
		output := e.kubectl("get", "pod", podName)
		if strings.Contains(output, "Completed") {
			break
		}
		time.Sleep(time.Second)
	}

	e.logf("Checking log enricher output")
	output := e.kubectlOperatorNS("logs", "ds/spod", "log-enricher")

	e.Contains(output, `"msg"="audit"`)
	e.Contains(output, `"type"="seccomp"`)
	e.Contains(output, `"executable"="/usr/sbin/nginx"`)
	e.Contains(output, fmt.Sprintf(`"pod"=%q`, podName))
	e.Contains(output, fmt.Sprintf(`"container"=%q`, containerName))
	e.Contains(output, fmt.Sprintf(`"namespace"=%q`, namespace))
	e.Contains(output, `"node"="127.0.0.1"`)
	e.Contains(output, `"pid"`)
	e.Contains(output, `"timestamp"`)
	e.Contains(output, `"syscallName"="listen"`)
	e.Contains(output, `"syscallID"=50`)
}
