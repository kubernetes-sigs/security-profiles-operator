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
	v1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/profile"
)

func (e *e2e) testCaseDefaultAndExampleProfiles(nodes []string) {
	const (
		exampleProfilePath = "examples/profile.yaml"
		exampleProfileName = "test-profile"
	)
	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	e.logf("Retrieving deployed example profile")
	exampleProfiles := e.getConfigMap(exampleProfileName, "default")

	// Get the default profiles
	e.logf("Retrieving default profiles from configmap: %s", config.DefaultProfilesConfigMapName)
	defaultProfiles := e.getConfigMap(
		config.DefaultProfilesConfigMapName, config.OperatorName,
	)

	// Content verification
	for _, node := range nodes {
		// General path verification
		e.logf("Verifying security profiles operator directory on node: %s", node)
		statOutput := e.execNode(
			node, "stat", "-L", "-c", `%a,%u,%g`, config.ProfilesRootPath,
		)
		e.Contains(statOutput, "744,2000,2000")

		// Default profile verification
		e.verifyProfilesContent(node, defaultProfiles)

		// Example profile verification
		e.verifyProfilesContent(node, exampleProfiles)
	}
}

func (e *e2e) verifyProfilesContent(node string, cm *v1.ConfigMap) {
	e.logf("Verifying %s profile on node %s", cm.Name, node)
	for name, content := range cm.Data {
		profilePath, err := profile.GetProfilePath(name, cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
		e.Nil(err)
		catOutput := e.execNode(node, "cat", profilePath)
		e.Contains(catOutput, content)
	}
}
