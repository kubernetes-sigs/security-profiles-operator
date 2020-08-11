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
	"io/ioutil"
	"os"
)

func (e *e2e) testCaseDeployInvalidProfile([]string) {
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
	invalidProfile, err := ioutil.TempFile("", "invalid-profile-")
	e.Nil(err)

	_, err = invalidProfile.WriteString(invalidProfileContent)
	e.Nil(err)
	e.kubectl("create", "-f", invalidProfile.Name())
	defer func() {
		e.kubectl("delete", "-f", invalidProfile.Name())
		e.Nil(os.RemoveAll(invalidProfile.Name()))
	}()

	// Verify the event
	eventsOutput := e.kubectl("get", "events")
	for _, s := range []string{
		"Warning",
		"cannot validate profile profile-invalid.json",
		"configmap/invalid-profile",
		"decoding seccomp profile: json: cannot unmarshal bool into " +
			"Go struct field Seccomp.defaultAction of type seccomp.Action",
	} {
		e.Contains(eventsOutput, s)
	}
}
