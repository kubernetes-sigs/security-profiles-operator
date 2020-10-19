// +build e2e

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
	"encoding/json"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/api/v1alpha1"
)

const manifest = "deploy/operator.yaml"

func (e *e2e) TestSeccompOperator() {
	// Deploy the operator
	e.deployOperator(manifest)
	defer e.run("git", "checkout", manifest)

	// Retrieve the inputs for the test cases
	nodes := e.getWorkerNodes()

	// Execute the test cases. Each test case should cleanup on its own and
	// leave a working operator behind.
	for _, testCase := range []struct {
		description string
		fn          func(nodes []string)
	}{
		{
			"Verify default and example profiles",
			e.testCaseDefaultAndExampleProfiles,
		},
		{
			"Run a test pod",
			e.testCaseRunPod,
		},
		{
			"Re-deploy the operator",
			e.testCaseReDeployOperator,
		},
		{
			"Deploy invalid profile",
			e.testCaseDeployInvalidProfile,
		},
		{
			"Verify example CRD profiles",
			e.testCaseCRDExampleProfiles,
		},
	} {
		e.logf("> Running testcase: %s", testCase.description)
		testCase.fn(nodes)
	}
}

func (e *e2e) deployOperator(manifest string) {
	// Ensure that we do not accidentally pull the image and use the pre-loaded
	// ones from the nodes
	e.logf("Setting imagePullPolicy to 'Never' in manifest: %s", manifest)
	e.run(
		"sed", "-i", "s;imagePullPolicy: Always;imagePullPolicy: Never;g",
		manifest,
	)

	// Update the image name to match the test image
	e.run(
		"sed", "-i", fmt.Sprintf("s;image: .*gcr.io/.*;image: %s;g", testImage),
		manifest,
	)

	// Deploy the operator
	e.logf("Deploying operator")
	e.kubectl("create", "-f", manifest)

	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "--all")
}

func (e *e2e) getWorkerNodes() []string {
	e.logf("Getting worker nodes")
	nodesOutput := e.kubectl(
		"get", "nodes",
		"-l", "node-role.kubernetes.io/master!=",
		"-o", `jsonpath={range .items[*]}{@.metadata.name}{" "}{end}`,
	)
	nodes := strings.Fields(nodesOutput)
	e.logf("Got worker nodes: %v", nodes)

	return nodes
}

func (e *e2e) getConfigMap(name, namespace string) *v1.ConfigMap {
	configMapJSON := e.kubectl(
		"-n", namespace, "get", "configmap", name, "-o", "json",
	)
	configMap := &v1.ConfigMap{}
	e.Nil(json.Unmarshal([]byte(configMapJSON), configMap))
	return configMap
}

func (e *e2e) getSeccompProfile(name, namespace string) *v1alpha1.SeccompProfile {
	seccompProfileJSON := e.kubectl(
		"-n", namespace, "get", "seccompprofile", name, "-o", "json",
	)
	seccompProfile := &v1alpha1.SeccompProfile{}
	e.Nil(json.Unmarshal([]byte(seccompProfileJSON), seccompProfile))
	return seccompProfile
}
