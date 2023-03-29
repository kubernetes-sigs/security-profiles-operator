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

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func (e *e2e) testCaseDefaultAndExampleProfiles(nodes []string) {
	e.seccompOnlyTestCase()
	const exampleProfilePath = "examples/seccompprofile.yaml"
	exampleProfileNames := [3]string{"profile-allow-unsafe", "profile-complain-unsafe", "profile-block-all"}
	e.kubectl("create", "-f", exampleProfilePath)
	defer e.kubectl("delete", "-f", exampleProfilePath)

	// Content verification
	for _, node := range nodes {
		// General path verification
		e.logf("Verifying security profiles operator directory on node: %s", node)

		// This symlink is not available on e2e-flatcar because the rootfs is mounted into
		// the dev container where the tests are executed. This check needs to be skipped.
		if e.nodeRootfsPrefix == "" {
			statOutput := e.execNode(
				node, "stat", "-L", "-c", `%a,%u,%g`, config.ProfilesRootPath(),
			)
			e.Contains(statOutput, "744,65535,65535")

			// security-profiles-operator.json init verification
			cm := e.getConfigMap(
				"security-profiles-operator-profile", config.OperatorName,
			)
			e.verifyBaseProfileContent(node, cm)
		}

		// Example profile verification
		namespace := e.getCurrentContextNamespace(defaultNamespace)
		for _, name := range exampleProfileNames {
			e.waitFor(
				"condition=ready",
				"--namespace", namespace,
				"seccompprofile", name,
			)
			sp := e.getSeccompProfile(name, namespace)
			e.verifyCRDProfileContent(node, sp)

			spns := e.getSeccompProfileNodeStatus(name, namespace, node)
			if e.NotNil(spns) {
				e.Equal(spns.Status, secprofnodestatusv1alpha1.ProfileStateInstalled)
			}
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

func (e *e2e) verifyCRDProfileContent(node string, sp *seccompprofileapi.SeccompProfile) {
	e.logf("Verifying %s profile on node %s", sp.Name, node)
	profilePath := path.Join(e.nodeRootfsPrefix, sp.GetProfileOperatorPath())
	catOutput := e.execNode(node, "cat", profilePath)
	output := seccompprofileapi.SeccompProfileSpec{}
	err := json.Unmarshal([]byte(catOutput), &output)
	e.Nil(err)
	expected := seccompprofileapi.SeccompProfileSpec{}
	spec, err := json.Marshal(sp.Spec)
	e.Nil(err)
	err = json.Unmarshal(spec, &expected)
	e.Nil(err)
	e.Equal(output, expected)
}
