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
	"fmt"
	"io/ioutil"
	"os"

	"sigs.k8s.io/seccomp-operator/internal/pkg/controllers/profile"
)

func (e *e2e) testCaseDeployInvalidProfile(nodes []string) {
	const (
		configMapName = "invalid-profile"
		profileName   = "profile-invalid.json"
	)

	newProfile := func(content string) string {
		configMapString := fmt.Sprintf(`---
apiVersion: v1
kind: ConfigMap
metadata:
  name: %s
  annotations:
    seccomp.security.kubernetes.io/profile: "true"
data:
  %s: |-
    %s
`, configMapName, profileName, content)
		configMapFile, err := ioutil.TempFile("", configMapName)
		e.Nil(err)
		_, err = configMapFile.WriteString(configMapString)
		e.Nil(err)
		return configMapFile.Name()
	}

	e.logf("Deploying invalid configMap")
	invalidProfile := newProfile(`{ "defaultAction": true }`)
	e.kubectl("create", "-f", invalidProfile)
	defer func() {
		e.kubectl("delete", "-f", invalidProfile)
		e.Nil(os.RemoveAll(invalidProfile))
	}()

	// Verify the event
	e.logf("Verifying events")
	eventsOutput := e.kubectl("get", "events")
	for _, s := range []string{
		"Warning",
		"InvalidSeccompProfile",
		"configmap/" + configMapName,
		"decoding seccomp profile: json: cannot unmarshal bool into " +
			"Go struct field Seccomp.defaultAction of type seccomp.Action",
	} {
		e.Contains(eventsOutput, s)
	}

	// Check that the profile is not reconciled to the node
	e.logf("Verifying node content")
	configMap := e.getConfigMap(configMapName, "default")
	profilePath, err := profile.GetProfilePath(profileName, configMap.ObjectMeta.Namespace, configMap.ObjectMeta.Name)
	e.Nil(err)
	for _, node := range nodes {
		e.execNode(node, "bash", "-c", fmt.Sprintf("[ ! -f %s ]", profilePath))
	}

	// Make the profile valid
	e.logf("Patching invalid configMap to be valid again")
	validProfile := newProfile(`{ "defaultAction": "SCMP_ACT_ALLOW" }`)
	e.kubectl("apply", "-f", validProfile)
	defer e.Nil(os.RemoveAll(validProfile))
	for _, node := range nodes {
		e.execNode(node, "bash", "-c", fmt.Sprintf("[ -f %s ]", profilePath))
	}
}
