/*
Copyright The Kubernetes Authors.

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

func (e *e2e) testCaseSPODUpdateSelinux([]string) {
	e.selinuxOnlyTestCase()

	e.logf("assert selinux is enabled in the spod object")

	selinuxEnabledInSPODObj := e.kubectlOperatorNS(
		"get",
		"spod",
		"spod",
		"-o",
		"jsonpath={.spec.selinux.enable}",
	)
	if clusterType == clusterTypeOpenShift {
		// OCP enables SELinux by default, so both no value and explicit true are OK
		if selinuxEnabledInSPODObj != "" && selinuxEnabledInSPODObj != "true" {
			e.Fail("Expected that SELinux is enabled explicitly or by default on OCP")
		}

		e.Empty(selinuxEnabledInSPODObj)
	} else {
		e.Equal("true", selinuxEnabledInSPODObj)
	}

	e.logf("assert selinux is enabled in the spod DS")
	selinuxEnabledInSPODDS := e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.Contains(selinuxEnabledInSPODDS, "--with-selinux=true")

	e.logf("Disable selinux from SPOD")
	e.patchSpod(`{"spec":{"selinux":{"enable": false}}}`)

	e.logf("assert selinux is disabled in the spod DS")
	selinuxDisabledInSPODDS := e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.NotContains(selinuxDisabledInSPODDS, "--with-selinux=true")

	e.logf("Re-enable selinux in SPOD")
	e.patchSpod(`{"spec":{"selinux":{"enable": true}}}`)

	e.logf("assert selinux is enabled in the spod DS")
	selinuxEnabledInSPODDS = e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	e.Contains(selinuxEnabledInSPODDS, "--with-selinux=true")
}
