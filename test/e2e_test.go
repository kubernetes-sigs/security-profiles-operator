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
	"io/ioutil"
	"strings"

	"github.com/kubernetes-sigs/seccomp-operator/internal/pkg/controllers/profile"
	v1 "k8s.io/api/core/v1"
)

func (e *e2e) TestSeccompOperator() {
	const manifest = "deploy/operator.yaml"
	defer e.cleanupOperator(manifest)
	defer e.run("git", "checkout", manifest)

	// Deploy the operator
	e.deployOperator(manifest)

	// Deploy the example profile
	const (
		exampleProfilePath = "examples/profile.yaml"
		exampleProfileName = "test-profile"
	)
	e.logf("Deploying example profile: %s", exampleProfilePath)
	e.kubectl("create", "-f", exampleProfilePath)

	e.logf("Retrieving deployed example profile")
	exampleProfileData := e.kubectl(
		"get", "configmap", exampleProfileName, "-o", "json",
	)

	exampleProfiles := &v1.ConfigMap{}
	e.logf("Unmarshalling example profiles JSON: %s", exampleProfileName)
	e.Nil(json.Unmarshal([]byte(exampleProfileData), exampleProfiles))

	// Verify that the default profiles are on all worker nodes
	e.logf("Verifying default profiles on all worker nodes")
	nodes := e.kubectl(
		"get", "nodes",
		"-l", "node-role.kubernetes.io/master!=",
		"-o", `jsonpath={range .items[*]}{@.metadata.name}{" "}{end}`,
	)
	e.logf("Got worker nodes: %v", nodes)

	// Get the default profiles
	e.logf("Retrieving default profiles from configmap: %s", profile.DefaultProfilesConfigMapName)
	defaultProfilesData := e.kubectlOperatorNS(
		"get", "configmap", profile.DefaultProfilesConfigMapName, "-o", "json",
	)
	defaultProfiles := &v1.ConfigMap{}
	e.logf("Unmarshalling default profiles JSON: %s", defaultProfilesData)
	e.Nil(json.Unmarshal([]byte(defaultProfilesData), defaultProfiles))

	// Content verification
	for _, node := range strings.Fields(nodes) {
		// General path verification
		e.logf("Verifying seccomp operator directory on node: %s", node)
		statOutput := e.execNode(
			node, "stat", "-L", "-c", `%a,%u,%g`, profile.ProfileRootPath,
		)
		e.Contains(statOutput, "744,2000,2000")

		// Default profile verification
		e.verifyProfilesContent(node, defaultProfiles)

		// Example profile verification
		e.verifyProfilesContent(node, exampleProfiles)
	}

	// Run the test pod
	const (
		examplePodPath = "examples/pod.yaml"
		examplePodName = "test-pod"
	)
	e.logf("Creating the test pod: %s", examplePodPath)
	e.kubectl("create", "-f", examplePodPath)

	e.logf("Waiting for test pod to be ready")
	e.kubectl("wait", "--for", "condition=ready", "pod", "--all")

	e.logf("Testing that `rmdir` is not possible inside the pod")
	failureOutput := e.kubectlFailure(
		"exec", examplePodName, "--", "rmdir", "/home",
	)
	e.Contains(failureOutput,
		"rmdir: failed to remove '/home': Operation not permitted",
	)

	e.logf("Cleaning up and re-deploying the operator")
	// Clean up the operator
	e.cleanupOperator(manifest)

	// Deploy the operator again
	e.deployOperator(manifest)

	e.deployInvalidProfile()

	e.logf("Tests succeeded")
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
		"sed", "-i", fmt.Sprintf("s;image: gcr.io/.*;image: %s;g", testImage),
		manifest,
	)

	// Deploy the operator
	e.logf("Deploying operator")
	e.kubectl("create", "-f", manifest)

	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "--all")
}

func (e *e2e) cleanupOperator(manifest string) {
	// Clean up the operator
	e.logf("Cleaning up operator")
	e.kubectl("delete", "-f", manifest)
}

func (e *e2e) verifyProfilesContent(node string, cm *v1.ConfigMap) {
	e.logf("Verifying %s profile on node %s", cm.Name, node)
	for name, content := range cm.Data {
		profilePath, err := profile.GetProfilePath(name, cm)
		e.Nil(err)
		catOutput := e.execNode(node, "cat", profilePath)
		e.Contains(catOutput, content)
	}
}

func (e *e2e) deployInvalidProfile() {
	const invalidProfileContent = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: invalid-profile
  annotations:
    seccomp.security.kubernetes.io/profile: "true"
data:
  profile-invalid.json: |-
    { "defaultAction": true }
`
	e.logf("Deploying an invalid profile")
	invalidProfile, err := ioutil.TempFile("", "invalid-profile-")
	e.Nil(err)
	_, err = invalidProfile.WriteString(invalidProfileContent)
	e.Nil(err)
	e.kubectl("create", "-f", invalidProfile.Name())

	// Verify the event
	eventsOutput := e.kubectl("get", "events")
	for _, s := range []string{
		"Warning",
		"cannot validate profile profile-invalid.json",
		"configmap/invalid-profile",
		"decoding seccomp profile: json: cannot unmarshal bool into " +
			"Go struct field Seccomp.defaultAction of type types.Action",
	} {
		e.Contains(eventsOutput, s)
	}
}
