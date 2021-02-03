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
	"io/ioutil"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
)

const (
	certmanager       = "https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml"
	manifest          = "deploy/operator.yaml"
	namespaceManifest = "deploy/namespace-operator.yaml"
	testNamespace     = "test-ns"
	defaultNamespace  = "default"
	// NOTE(jaosorior): We should be able to decrease this once we
	// migrate to a single daemonset-based implementation for the
	// SELinux pieces.
	defaultSelinuxOpTimeout = "360s"
	defaultWaitTime         = 5 * time.Second
)

func (e *e2e) TestSecurityProfilesOperator() {
	// Deploy the operator
	e.deployOperator(manifest)
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
			"Seccomp: Verify default and example profiles",
			e.testCaseDefaultAndExampleProfiles,
		},
		{
			"Seccomp: Run a test pod",
			e.testCaseRunPod,
		},
		{
			"Seccomp: Verify base profile merge",
			e.testCaseBaseProfile,
		},
		{
			"Seccomp: Delete profiles",
			e.testCaseDeleteProfiles,
		},
		{
			"Seccomp: Re-deploy the operator",
			e.testCaseReDeployOperator,
		},
		{
			"SELinux: sanity check",
			e.testCaseSelinuxSanityCheck,
		},
		{
			"SELinux: base case (install policy, run pod and delete)",
			e.testCaseSelinuxBaseUsage,
		},
	}
	for _, testCase := range testCases {
		tc := testCase
		e.Run("cluster-wide: "+tc.description, func() {
			tc.fn(nodes)
		})
	}

	// TODO(jaosorior): Re-introduce this to the namespaced tests once we
	// fix the issue with the certs.
	e.Run("cluster-wide: Seccomp: Verify profile binding", func() {
		e.testCaseProfileBinding(nodes)
	})

	// Clean up cluster-wide deployment to prepare for namespace deployment
	e.cleanupOperator(manifest)

	e.logf("testing namespace operator")

	// Use namespace manifests for redeploy test
	testCases[4].fn = e.testCaseReDeployNamespaceOperator

	// Deploy the namespace operator
	e.kubectl("create", "namespace", testNamespace)
	e.run(
		"sed", "-i", fmt.Sprintf("s/NS_REPLACE/%s/", testNamespace),
		namespaceManifest,
	)
	defer e.run("git", "checkout", namespaceManifest)
	// All following operations such as create pod will be in the test namespace
	e.kubectl("config", "set-context", "--current", "--namespace", testNamespace)
	e.deployOperator(namespaceManifest)

	for _, testCase := range testCases {
		tc := testCase
		e.Run("namespaced: "+tc.description, func() {
			tc.fn(nodes)
		})
	}
}

func (e *e2e) deployOperator(manifest string) {
	// Ensure that we do not accidentally pull the image and use the pre-loaded
	// ones from the nodes
	e.logf("Setting imagePullPolicy to '%s' in manifest: %s", e.pullPolicy, manifest)
	e.run(
		"sed", "-i",
		fmt.Sprintf("s;imagePullPolicy: Always;imagePullPolicy: %s;g", e.pullPolicy),
		manifest,
	)
	e.run(
		"sed", "-i", fmt.Sprintf("s;SPOdImagePullPolicy: Always;SPOdImagePullPolicy: %s;g", e.pullPolicy),
		manifest,
	)

	// Update the image name to match the test image
	e.run(
		"sed", "-i", fmt.Sprintf("s;image: .*gcr.io/.*;image: %s;g", e.testImage),
		manifest,
	)
	e.run(
		"sed", "-i", fmt.Sprintf("s;value: .*gcr.io/.*;value: %s;g", e.testImage),
		manifest,
	)

	if e.platformSupportsSelinux() {
		e.run(
			"sed", "-i", "s/EnableSelinux: \"false\"/EnableSelinux: \"true\"/",
			manifest,
		)
	}

	// Deploy the operator
	e.logf("Deploying operator")
	e.kubectl("create", "-f", manifest)

	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	// Wait for deployment
	e.kubectlOperatorNS("wait", "--for", "condition=available", "deployment", "-l", "app=security-profiles-operator")
	// Wait for all pods in deployment
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "-l", "app=security-profiles-operator")
	// Wait for all pods in DaemonSet
	time.Sleep(defaultWaitTime)
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "-l", "app=spod")
}

func (e *e2e) cleanupOperator(manifest string) {
	// Clean up the operator
	e.logf("Cleaning up operator")
	e.kubectl("delete", "seccompprofiles", "--all", "--all-namespaces")
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

func (e *e2e) writeAndCreate(manifest, filePattern string) func() {
	file, err := ioutil.TempFile(os.TempDir(), filePattern)
	fileName := file.Name()
	e.Nil(err)
	_, err = file.Write([]byte(manifest))
	e.Nil(err)
	err = file.Close()
	e.Nil(err)
	e.kubectl("create", "-f", fileName)
	return func() { os.Remove(fileName) }
}

func (e *e2e) getSELinuxPolicyName(policy string) string {
	usageStr := e.getSELinuxPolicyUsage(policy)
	// Udica (the library that helps out generate SELinux policies),
	// adds .process in the end of the usage. So we need to remove it
	// to get the module name
	return strings.TrimSuffix(usageStr, ".process")
}

func (e *e2e) getSELinuxPolicyUsage(policy string) string {
	ns := e.getCurrentContextNamespace(defaultNamespace)
	// This describes the usage string, which is not necessarily
	// the name of the policy in the node
	return e.kubectl("get", "selinuxpolicy", "-n", ns, policy, "-o", "jsonpath={.status.usage}")
}

func (e *e2e) sliceContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
