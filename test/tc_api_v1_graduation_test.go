/*
Copyright 2026 The Kubernetes Authors.

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
)

func (e *e2e) testCaseAPIV1Graduation(_ []string) {
	e.logf("Testing API v1 graduation conversion webhooks")

	e.testSeccompProfileConversion()
	e.testProfileRecordingConversion()
}

func (e *e2e) testSeccompProfileConversion() {
	e.seccompOnlyTestCase()

	e.logf("Testing SeccompProfile v1beta1 -> v1 conversion")

	const (
		v1beta1Profile = `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: test-v1beta1-conversion
spec:
  defaultAction: "SCMP_ACT_ERRNO"
  syscalls:
  - names:
    - read
    - write
    - exit_group
    action: "SCMP_ACT_ALLOW"
`
		profileName = "test-v1beta1-conversion"
	)

	cleanup := e.writeAndCreate(v1beta1Profile, "v1beta1-seccomp-*.yaml")
	defer cleanup()
	defer e.kubectl("delete", "seccompprofile", profileName)

	e.logf("Waiting for v1beta1 SeccompProfile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Verifying v1beta1 profile is accessible via v1 API")
	sp := e.getSeccompProfile(profileName)
	e.Equal("SCMP_ACT_ERRNO", string(sp.Spec.DefaultAction))
	e.Require().NotEmpty(sp.Spec.Syscalls)
	e.Equal("SCMP_ACT_ALLOW", string(sp.Spec.Syscalls[0].Action))
	e.Contains(sp.Spec.Syscalls[0].Names, "read")
	e.Contains(sp.Spec.Syscalls[0].Names, "write")
	e.Contains(sp.Spec.Syscalls[0].Names, "exit_group")

	e.logf("Verifying round-trip back to v1beta1")
	v1beta1JSON := e.kubectl(
		"get",
		"seccompprofiles.v1beta1.security-profiles-operator.x-k8s.io",
		profileName, "-o", "json",
	)

	var v1beta1Result map[string]any
	e.Require().NoError(json.Unmarshal([]byte(v1beta1JSON), &v1beta1Result))

	spec, ok := v1beta1Result["spec"].(map[string]any)
	e.Require().True(ok, "spec should be a map")
	e.Equal("SCMP_ACT_ERRNO", spec["defaultAction"])

	syscalls, ok := spec["syscalls"].([]any)
	e.Require().True(ok, "syscalls should be a list")
	e.Require().NotEmpty(syscalls)

	firstSyscall, ok := syscalls[0].(map[string]any)
	e.Require().True(ok)
	e.Equal("SCMP_ACT_ALLOW", firstSyscall["action"])

	e.logf("SeccompProfile v1beta1 <-> v1 conversion verified")
}

func (e *e2e) testProfileRecordingConversion() {
	e.logf("Testing ProfileRecording v1alpha1 -> v1 enum conversion")

	const (
		v1alpha1Recording = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: test-v1alpha1-conversion
spec:
  kind: SeccompProfile
  recorder: logs
  mergeStrategy: none
  podSelector:
    matchLabels:
      app: test-recording
`
		recordingName = "test-v1alpha1-conversion"
	)

	cleanup := e.writeAndCreate(v1alpha1Recording, "v1alpha1-recording-*.yaml")
	defer cleanup()
	defer e.kubectl("delete", "profilerecording", recordingName)

	e.logf("Verifying v1alpha1 recording is accessible via v1 API with PascalCase enums")
	v1JSON := e.kubectl("get", "profilerecording", recordingName, "-o", "json")

	var v1Result map[string]any
	e.Require().NoError(json.Unmarshal([]byte(v1JSON), &v1Result))

	spec, ok := v1Result["spec"].(map[string]any)
	e.Require().True(ok, "spec should be a map")
	e.Equal("Logs", spec["recorder"], "v1 recorder should be PascalCase 'Logs'")
	e.Equal("None", spec["mergeStrategy"], "v1 mergeStrategy should be PascalCase 'None'")
	e.Equal("SeccompProfile", spec["kind"], "kind should be preserved")

	e.logf("Verifying round-trip back to v1alpha1 with lowercase enums")
	v1alpha1JSON := e.kubectl(
		"get",
		"profilerecordings.v1alpha1.security-profiles-operator.x-k8s.io",
		recordingName, "-o", "json",
	)

	var v1alpha1Result map[string]any
	e.Require().NoError(json.Unmarshal([]byte(v1alpha1JSON), &v1alpha1Result))

	spec, ok = v1alpha1Result["spec"].(map[string]any)
	e.Require().True(ok, "spec should be a map")
	e.Equal("logs", spec["recorder"], "v1alpha1 recorder should be lowercase 'logs'")
	e.Equal("none", spec["mergeStrategy"], "v1alpha1 mergeStrategy should be lowercase 'none'")

	e.logf("ProfileRecording v1alpha1 <-> v1 enum conversion verified")
}
