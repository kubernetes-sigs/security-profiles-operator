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
	"io/ioutil"
	"os"
	"strings"
)

func (e *e2e) testCaseProfileBinding([]string) {
	if !e.runExperimental {
		e.T().Skip("skipping experimental test")
	}
	const exampleProfilePath = "examples/seccompprofile.yaml"
	const testBinding = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileBinding
metadata:
  name: hello-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-allow
  image: hello-world
`
	const testPod = `
apiVersion: v1
kind: Pod
metadata:
  name: hello
spec:
  containers:
  - image: hello-world
    name: hello
    resources: {}
  restartPolicy: Never
`
	const manifest = "deploy/webhook.yaml"

	e.deployWebhook(manifest)
	defer e.run("git", "checkout", manifest)
	defer e.cleanupWebhook(manifest)

	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	e.logf("Creating test profile binding")
	testBindingFile, err := ioutil.TempFile(os.TempDir(), "hello-binding*.yaml")
	e.Nil(err)
	defer os.Remove(testBindingFile.Name())
	_, err = testBindingFile.Write([]byte(testBinding))
	e.Nil(err)
	err = testBindingFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", testBindingFile.Name())
	defer e.kubectl("delete", "-f", testBindingFile.Name())

	e.logf("Creating test pod")
	testPodFile, err := ioutil.TempFile(os.TempDir(), "hello-pod*.yaml")
	e.Nil(err)
	defer os.Remove(testPodFile.Name())

	_, err = testPodFile.Write([]byte(testPod))
	e.Nil(err)
	err = testPodFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", testPodFile.Name())
	defer e.kubectl("delete", "pod", "hello")

	e.logf("Waiting for test pod to be initialized")
	e.kubectl("wait", "--for", "condition=initialized", "pod", "hello")

	output := e.kubectl("get", "pod", "hello")
	for strings.Contains(output, "ContainerCreating") {
		output = e.kubectl("get", "pod", "hello")
	}

	e.logf("Testing that container is launched without runtime permission errors")
	output = e.kubectl("describe", "pod", "hello")
	e.NotContains(output, "Error: failed to start containerd task")

	e.logf("Testing that container ran successfully")
	output = e.kubectl("logs", "hello")
	e.Contains(output, "Hello from Docker!")

	namespace := e.getCurrentContextNamespace(defaultNamespace)

	e.logf("Testing that pod has securityContext")
	output = e.kubectl(
		"get", "pod", "hello",
		"--output", "jsonpath={.spec.containers[0].securityContext.seccompProfile.localhostProfile}",
	)
	e.Equal(fmt.Sprintf("operator/%s/example-profiles/profile-allow.json", namespace), output)

	e.logf("Testing that profile binding has pod reference")
	output = e.kubectl("get", "profilebinding", "hello-binding", "--output", "jsonpath={.status.activeWorkloads[0]}")
	e.Equal(fmt.Sprintf("%s/hello", namespace), output)
	output = e.kubectl("get", "profilebinding", "hello-binding", "--output", "jsonpath={.metadata.finalizers[0]}")
	e.Equal("active-workload-lock", output)

	e.logf("Testing that profile has pod reference")
	output = e.kubectl("get", "seccompprofile", "profile-allow", "--output", "jsonpath={.status.activeWorkloads[0]}")
	e.Equal(fmt.Sprintf("%s/hello", namespace), output)
	output = e.kubectl("get", "seccompprofile", "profile-allow", "--output", "jsonpath={.metadata.finalizers}")
	e.Contains(output, "in-use-by-active-pods")
}

func (e *e2e) deployWebhook(manifest string) {
	// Deploy prerequisites
	e.logf("Deploying cert-manager")
	e.kubectl("apply", "-f", certmanager)
	e.kubectl(
		"--namespace", "cert-manager",
		"wait", "--for", "condition=ready",
		"pod", "-l", "app.kubernetes.io/instance=cert-manager",
	)
	e.run(
		"sed", "-i", fmt.Sprintf("s;image: .*gcr.io/.*;image: %s;g", e.testImage),
		manifest,
	)
	e.run(
		"sed", "-i",
		fmt.Sprintf("s;imagePullPolicy: Always;imagePullPolicy: %s;g", e.pullPolicy),
		manifest,
	)
	e.logf("Deploying webhook")
	e.kubectl("create", "-f", manifest)
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "-l", "name=security-profiles-operator-webhook")
}

func (e *e2e) cleanupWebhook(manifest string) {
	e.logf("Cleaning up webhook")
	e.kubectl("delete", "-f", manifest)
	e.kubectl("delete", "-f", certmanager)
}
