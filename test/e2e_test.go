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

	"sigs.k8s.io/security-profiles-operator/api/v1alpha1"
)

const (
	manifest                 = "deploy/operator.yaml"
	namespaceManifest        = "deploy/namespace-operator.yaml"
	defaultProfiles          = "deploy/profiles/default-profiles.yaml"
	namespaceDefaultProfiles = "deploy/profiles/namespace-default-profiles.yaml"
	testNamespace            = "test-ns"
	defaultNamespace         = "default"
)

func (e *e2e) TestSeccompOperator() {
	// Deploy the operator
	e.deployOperator(manifest, defaultProfiles)
	defer e.run("git", "checkout", manifest)

	// Retrieve the inputs for the test cases
	nodes := e.getWorkerNodes()

	// Execute the test cases. Each test case should cleanup on its own and
	// leave a working operator behind.
	e.logf("testing cluster-wide operator")
	testCases := []struct {
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
			"Verify base profile merge",
			e.testCaseBaseProfile,
		},
		{
			"Delete profiles",
			e.testCaseDeleteProfiles,
		},
		{
			"Re-deploy the operator",
			e.testCaseReDeployOperator,
		},
	}
	for _, testCase := range testCases {
		e.logf("> Running testcase: %s", testCase.description)
		testCase.fn(nodes)
	}

	// Clean up cluster-wide deployment to prepare for namespace deployment
	e.cleanupOperator(manifest, defaultProfiles)

	e.logf("testing namespace operator")

	// Use namespace manifests for redeploy test
	testCases[4].fn = e.testCaseReDeployNamespaceOperator

	// Deploy the namespace operator
	e.kubectl("create", "namespace", testNamespace)
	e.run(
		"sed", "-i", fmt.Sprintf("s/NS_REPLACE/%s/", testNamespace),
		namespaceManifest,
	)
	e.run(
		"sed", "-i", fmt.Sprintf("s/NS_REPLACE/%s/", testNamespace),
		namespaceDefaultProfiles,
	)
	defer e.run("git", "checkout", namespaceManifest)
	defer e.run("git", "checkout", namespaceDefaultProfiles)
	// All following operations such as create pod will be in the test namespace
	e.kubectl("config", "set-context", "--current", "--namespace", testNamespace)
	e.deployOperator(namespaceManifest, namespaceDefaultProfiles)

	for _, testCase := range testCases {
		e.logf("> Running testcase: %s", testCase.description)
		testCase.fn(nodes)
	}
}

func (e *e2e) deployOperator(manifest, profiles string) {
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

	// Deploy the default profiles
	e.logf("Deploying default profiles")
	e.kubectl("create", "-f", profiles)

	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "--all")
}

func (e *e2e) cleanupOperator(manifest, profiles string) {
	// Clean up the operator
	e.logf("Cleaning up operator")
	e.kubectl("delete", "-f", profiles)
	e.kubectl("delete", "-f", manifest)
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

func (e *e2e) getSeccompProfile(name, namespace string) *v1alpha1.SeccompProfile {
	seccompProfileJSON := e.kubectl(
		"-n", namespace, "get", "seccompprofile", name, "-o", "json",
	)
	seccompProfile := &v1alpha1.SeccompProfile{}
	e.Nil(json.Unmarshal([]byte(seccompProfileJSON), seccompProfile))
	return seccompProfile
}

func (e *e2e) getCurrentContextNamespace(alt string) string {
	ctxns := e.kubectl("config", "view", "--minify", "-o", "jsonpath={..namespace}")
	if ctxns == "" {
		ctxns = alt
	}
	return ctxns
}
