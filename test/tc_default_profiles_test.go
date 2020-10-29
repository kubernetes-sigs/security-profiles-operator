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
	"path"

	v1 "k8s.io/api/core/v1"

	v1alpha1 "sigs.k8s.io/security-profiles-operator/api/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/profile"
)

func (e *e2e) testCaseDefaultAndExampleProfiles(nodes []string) {
	const exampleProfilePath = "examples/seccompprofile.yaml"
	exampleProfileNames := [3]string{"profile-allow", "profile-complain", "profile-block"}
	defaultProfileNames := [1]string{"nginx-1.19.1"}
	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	// Content verification
	for _, node := range nodes {
		// General path verification
		e.logf("Verifying security profiles operator directory on node: %s", node)
		statOutput := e.execNode(
			node, "stat", "-L", "-c", `%a,%u,%g`, config.ProfilesRootPath,
		)
		e.Contains(statOutput, "744,2000,2000")

		// security-profiles-operator.json init verification
		cm := e.getConfigMap(
			"security-profiles-operator-profile", config.OperatorName,
		)
		e.verifyBaseProfileContent(node, cm)

		// Default profile verification
		for _, name := range defaultProfileNames {
			sp := e.getSeccompProfile(name, "security-profiles-operator")
			e.verifyCRDProfileContent(node, sp)
		}

		// Example profile verification
		for _, name := range exampleProfileNames {
			sp := e.getSeccompProfile(name, "default")
			e.verifyCRDProfileContent(node, sp)
		}
	}
}

func (e *e2e) getConfigMap(name, namespace string) *v1.ConfigMap {
	configMapJSON := e.kubectl(
		"-n", namespace, "get", "configmap", name, "-o", "json",
	)
	configMap := &v1.ConfigMap{}
	e.Nil(json.Unmarshal([]byte(configMapJSON), configMap))
	return configMap
}

func (e *e2e) verifyBaseProfileContent(node string, cm *v1.ConfigMap) {
	e.logf("Verifying %s profile on node %s", cm.Name, node)
	name := "security-profiles-operator.json"
	content := cm.Data[name]
	profilePath := path.Join("/var/lib/kubelet/seccomp", name)
	catOutput := e.execNode(node, "cat", profilePath)
	e.Contains(content, catOutput)
}

func (e *e2e) verifyCRDProfileContent(node string, sp *v1alpha1.SeccompProfile) {
	e.logf("Verifying %s profile on node %s", sp.Name, node)
	name := sp.Name
	expected, err := json.Marshal(sp.Spec)
	e.Nil(err)
	profilePath, err := profile.GetProfilePath(name, sp.ObjectMeta.Namespace, sp.Spec.TargetWorkload)
	e.Nil(err)
	catOutput := e.execNode(node, "cat", profilePath)
	e.Contains(catOutput, string(expected))
}
