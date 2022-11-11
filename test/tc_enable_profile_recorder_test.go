/*
Copyright 2022 The Kubernetes Authors.

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

import "time"

func (e *e2e) testCaseSPODEnableProfileRecorder(nodes []string) {
	e.enableLogEnricherInSpod()

	e.logf("assert profile recorder is enabled in the spod DS when log enricher is enabled")
	profileRecorderEnabledInSPODDS := e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.Contains(profileRecorderEnabledInSPODDS, "--with-recording=true")

	e.logf("Disable log enricher from SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableLogEnricher": false}}`, "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.logf("assert profile recorder is disabled in the spod DS when log enricher is disabled")
	selinuxDisabledInSPODDS := e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.NotContains(selinuxDisabledInSPODDS, "--with-recording=false")

	e.enableBpfRecorderInSpod()
	e.logf("assert profile recorder is enabled in the spod DS when bpf recorder is enabled")
	profileRecorderEnabledInSPODDS = e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.Contains(profileRecorderEnabledInSPODDS, "--with-recording=true")

	e.logf("Disable bpf recorder from SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableBpfRecorder": false}}`, "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.logf("assert profile recorder is disabled in the spod DS when bpf recorder is disabled")
	selinuxDisabledInSPODDS = e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.NotContains(selinuxDisabledInSPODDS, "--with-recording=false")
}
