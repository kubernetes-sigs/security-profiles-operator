/*
Copyright 2020 The Kubernetes Authors.

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

func (e *e2e) testCaseRunPod([]string) {
	e.seccompOnlyTestCase()
	const (
		examplePodPath = "examples/pod.yaml"
		examplePodName = "test-pod"
	)

	namespace := e.getCurrentContextNamespace(defaultNamespace)
	if namespace != defaultNamespace {
		e.updateManifest(examplePodPath, "security-profiles-operator", namespace)
		defer e.run("git", "checkout", examplePodPath)
	}

	e.logf("Creating the test pod: %s", examplePodPath)
	e.kubectl("create", "-f", examplePodPath)
	defer e.kubectl("delete", "-f", examplePodPath)

	e.logf("Waiting for test pod to be ready")
	e.waitFor("condition=ready", "pod", "--all")

	e.logf("Testing that `rmdir` is not possible inside the pod")
	failureOutput := e.kubectlFailure(
		"exec", examplePodName, "--", "rmdir", "/home",
	)
	e.Contains(failureOutput,
		"rmdir: failed to remove '/home': Operation not permitted",
	)
}
