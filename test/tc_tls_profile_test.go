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

func (e *e2e) testCaseTLSProfileOpenShift([]string) {
	if clusterType != clusterTypeOpenShift {
		e.T().Skip("Skipping OpenShift-only TLS profile test")
	}

	e.logf("Verify operator starts with correct TLS configuration on OpenShift")

	// Verify that operator pods are running (TLS config is applied at startup)
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "app=security-profiles-operator")

	// Verify the operator deployment logs show TLS watcher was enabled
	operatorLogs := e.kubectlOperatorNS("logs", "-l", "app=security-profiles-operator", "--tail=100")
	e.Contains(operatorLogs, "TLS profile watcher enabled")

	// Verify the daemon pods also have TLS watcher enabled
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "name=spod")
	spodLogs := e.kubectlOperatorNS("logs", "-l", "name=spod", "-c", "security-profiles-operator", "--tail=100")
	e.Contains(spodLogs, "TLS profile watcher enabled")

	// Verify HTTP/1.1 is enforced (HTTP/2 disabled as part of TLS config)
	webhookOutput := e.runAndRetryPodCMD(curlHTTPVerCMD + webhooksURL + "mutate-v1-pod-binding")
	e.Contains(webhookOutput, "1.1")

	e.logf("TLS profile verification passed on OpenShift")
}
