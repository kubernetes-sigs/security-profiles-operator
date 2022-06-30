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

import (
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func (e *e2e) testCaseRunPod([]string) {
	e.seccompOnlyTestCase()
	const (
		examplePodPath = "examples/pod.yaml"
		examplePodName = "test-pod"
		testPodFname   = "test-pod.yaml"
	)

	namespace := e.getCurrentContextNamespace(defaultNamespace)

	e.setupRecordingSa(namespace)

	if namespace != defaultNamespace {
		e.updateManifest(examplePodPath, "security-profiles-operator", namespace)
		defer e.run("git", "checkout", examplePodPath)
	}

	bs, err := os.ReadFile(examplePodPath)
	e.Nil(err)

	var testPod corev1.Pod
	err = yaml.Unmarshal(bs, &testPod)
	e.Nil(err)

	// the example pod runs as root by default. Since this is a valid and valuable
	// test case, but at the same time we don't want to pollute the example with OCP
	// specific settings, let's change the pod on the fly when running on OCP.
	if clusterType == clusterTypeOpenShift {
		zero := int64(0)

		// without anyuid, the pod can't set a custom UID
		testPod.Annotations["openshift.io/scc"] = "anyuid"
		// this SA allows using more privileged SCCs
		testPod.Spec.ServiceAccountName = "recording-sa"
		// force running as root
		for cidx := range testPod.Spec.Containers {
			cnt := &testPod.Spec.Containers[cidx]
			cnt.SecurityContext = &corev1.SecurityContext{
				RunAsUser: &zero,
			}
		}
	}

	e.logf("Creating the test pod: %s", examplePodPath)
	testPodBytes, err := yaml.Marshal(testPod)
	e.Nil(err)
	testPodManifest := string(testPodBytes)
	deleteCurNsFn := e.writeAndCreate(testPodManifest, testPodFname)
	defer e.kubectl("delete", "pods", examplePodName)
	defer deleteCurNsFn()

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
