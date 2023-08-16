/*
Copyright 2023 The Kubernetes Authors.

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
	"os"
	"strings"
	"time"
)

func (e *e2e) testCaseBaseProfileOCI([]string) {
	e.seccompOnlyTestCase()

	baseProfileName := "oci://ghcr.io/security-profiles/"

	if clusterType == clusterTypeVanilla && e.containerRuntime != containerRuntimeDocker {
		baseProfileName += strings.ReplaceAll(baseProfileNameCrun, "-", ":")
	} else {
		baseProfileName += strings.ReplaceAll(baseProfileNameRunc, "-", ":")
	}

	namespace := e.getCurrentContextNamespace(defaultNamespace)
	profileName := fmt.Sprintf("profile-%v", time.Now().Unix())
	profileYAML := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
  namespace: %s
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: %s
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - arch_prctl
    - set_tid_address
    - exit_group
`, profileName, namespace, baseProfileName)

	podName := fmt.Sprintf("pod-%v", time.Now().Unix())
	podYAML := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-hello-world:latest
    name: ctr
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/%s/%s.json
  restartPolicy: OnFailure
`, podName, namespace, namespace, profileName)

	e.logf("Creating profile")
	profileFile, err := os.CreateTemp("", "profile-*.yaml")
	e.Nil(err)
	defer os.Remove(profileFile.Name())

	_, err = profileFile.WriteString(profileYAML)
	e.Nil(err)
	err = profileFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", profileFile.Name())
	defer e.kubectl("delete", "-f", profileFile.Name())

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Creating pod")
	podFile, err := os.CreateTemp("", "pod-*.yaml")
	e.Nil(err)
	defer os.Remove(podFile.Name())

	_, err = podFile.WriteString(podYAML)
	e.Nil(err)
	err = podFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", podFile.Name())
	defer e.kubectl("delete", "pod", podName)

	e.logf("Waiting for test pod to be initialized")
	e.waitFor("condition=initialized", "pod", podName)

	e.logf("Waiting for pod to be completed")
	for i := 0; i < 20; i++ {
		output := e.kubectl("get", "pod", podName)
		if strings.Contains(output, "Completed") {
			break
		}
		if strings.Contains(output, "CreateContainerError") {
			e.kubectlOperatorNS("logs", "-l", "name=spod")
			output := e.kubectl("describe", "pod", podName)
			e.FailNowf("Unable to create container", output)
		}
		time.Sleep(time.Second)
	}

	e.logf("Testing that container ran successfully")
	output := e.kubectl("logs", podName)
	e.Contains(output, "Hello from Docker!")
}
