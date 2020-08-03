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
	"path/filepath"
	"strings"

	"github.com/kubernetes-sigs/seccomp-operator/internal/pkg/controllers/profile"
	v1 "k8s.io/api/core/v1"
)

func (e *e2e) TestSeccompOperator() {
	const manifest = "deploy/operator.yaml"

	// Ensure that we do not accidentally pull the image and use the pre-loaded
	// ones from the nodes
	e.logf("Setting imagePullPolicy to 'Never' in manifest: %s", manifest)
	e.run(
		"sed", "-i", "s;imagePullPolicy: Always;imagePullPolicy: Never;g",
		manifest,
	)
	defer e.run("git", "checkout", manifest)

	// Deploy the operator
	e.logf("Deploying operator")
	e.kubectl("create", "-f", manifest)

	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	e.kubectlOperatorNS("wait", "--for", "condition=ready", "pod", "--all")

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
	var defaultProfiles v1.ConfigMap
	e.logf("Unmarshalling default profiles JSON: %s", defaultProfilesData)
	e.Nil(json.Unmarshal([]byte(defaultProfilesData), &defaultProfiles))

	for _, node := range strings.Fields(nodes) {
		// General path verification
		e.logf("Verifying seccomp operator directory on node: %s", node)
		statOutput := e.run(
			"docker", "exec", node, "stat", "-c", `%a,%u,%g`, profile.DirTargetPath(),
		)
		e.Contains(statOutput, "744,2000,2000")

		// Default profile verification
		e.logf("Verifying default profiles on node: %s", node)
		for name, content := range defaultProfiles.Data {
			catOutput := e.run(
				"docker", "exec", node, "cat",
				filepath.Join(profile.DirTargetPath(), profile.DefaultProfilesConfigMapName, name),
			)
			e.Contains(catOutput, content)
		}
	}
}
