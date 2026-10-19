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
	"strings"
	"time"
)

func (e *e2e) testCaseSeccompProfileBinding(_ []string, image string) {
	e.seccompOnlyTestCase()

	const exampleProfilePath = "examples/seccompprofile.yaml"

	testBinding := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  name: hello-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-allow-unsafe
  image: %s
`, image)

	// The pod keeps running after it printed its line: the trackers release
	// a completed pod from the binding and the profile, which the checks
	// below look for.
	const testPod = `
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
  - image: busybox:latest
    name: hello
    command: ["sh", "-c", "echo Hello from the bound container; exec sleep 3600"]
    resources: {}
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      runAsUser: 1000
      runAsNonRoot: true
  restartPolicy: Never
  terminationGracePeriodSeconds: 1
`

	restoreNs := e.switchToNs(nsBindingEnabled)
	defer restoreNs()

	e.enableBindingHookInNs(nsBindingEnabled)

	e.kubectl("create", "-f", exampleProfilePath)
	e.kubectlCleanup("-f", exampleProfilePath)

	e.waitFor("condition=ready", "seccompprofile", "profile-allow-unsafe")

	e.logf("Creating test profile binding")

	e.writeAndCreate(testBinding, "hello-binding*.yaml")

	e.kubectlCleanup("profilebinding", "hello-binding")

	e.logf("Creating test pod")

	e.writeAndCreate(testPod, "hello-pod*.yaml")

	e.kubectlCleanup("pod", "hello")

	e.logf("Waiting for test pod to be ready")
	e.waitFor("condition=ready", "pod", "hello")

	e.logf("Testing that container is launched without runtime permission errors")
	output := e.kubectl("describe", "pod", "hello")
	e.NotContains(output, "Error: failed to start containerd task")

	e.logf("Testing that container ran successfully")
	e.eventually(podStartTimeout, time.Second, func() error {
		logs := e.kubectl("logs", "hello")
		if !strings.Contains(logs, "Hello from the bound container") {
			return fmt.Errorf("container did not print its line yet: %q", logs)
		}

		return nil
	})

	namespace := e.getCurrentContextNamespace(defaultNamespace)

	// Seccomp profiles are cluster scoped, their files have no namespace
	// directory.
	if image == "*" || image == "'*'" {
		e.logf("Profile Binding has * image, Testing that pod has securityContext")
		output = e.kubectl(
			"get", "pod", "hello",
			"--output", "jsonpath={.spec.securityContext.seccompProfile.localhostProfile}",
		)
		e.Equal("operator/profile-allow-unsafe.json", output)
	} else {
		e.logf("Testing that pod container has securityContext for specific image")
		output = e.kubectl(
			"get",
			"pod",
			"hello",
			"--output",
			"jsonpath={.spec.containers[0].securityContext.seccompProfile.localhostProfile}",
		)
		e.Equal("operator/profile-allow-unsafe.json", output)
	}

	e.logf("Testing that profile binding has pod reference")

	e.eventually(statusUpdateTimeout, time.Second, func() error {
		output = e.kubectl(
			"get", "profilebinding", "hello-binding",
			"--output", "jsonpath={.status.activeWorkloads[0]}",
		)
		if output != namespace+"/hello" {
			return fmt.Errorf("activeWorkloads not yet set: %s", output)
		}

		return nil
	})

	e.eventually(statusUpdateTimeout, time.Second, func() error {
		output = e.kubectl(
			"get", "profilebinding", "hello-binding",
			"--output", "jsonpath={.metadata.finalizers[0]}",
		)
		if output != "active-workload-lock" {
			return fmt.Errorf("finalizer not yet set: %s", output)
		}

		return nil
	})

	e.logf("Testing that profile has pod reference")
	output = e.kubectl("get", "seccompprofile", "profile-allow-unsafe",
		"--output", "jsonpath={.status.activeWorkloads[0]}")

	e.Equal(namespace+"/hello", output)

	// The finalizer gets added after the status.
	e.waitForProfileActivePodsFinalizer("profile-allow-unsafe")
}
