/*
Copyright 2021 The Kubernetes Authors.

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
	"time"
)

func (e *e2e) testCaseProfilingChange([]string) {
	e.logf("Change profiling in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableProfiling": true}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	logs := e.kubectlOperatorNS(
		"logs",
		"ds/spod",
		"security-profiles-operator",
	)

	e.Contains(logs, "Profiling support enabled: true")
}

func (e *e2e) testCaseProfilingHTTP([]string) {
	e.logf("Test profiling HTTP version")

	e.logf("Enable spod profiling to test endpoint HTTP version")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableProfiling": true}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	// lets only check the first spod pod
	podIP := e.kubectlOperatorNS("get", "pods", "-l", "name=spod", "-o", "jsonpath={.items[0].status.podIP}")
	podPort := e.kubectlOperatorNS("get", "pods", "-l", "name=spod", "-o",
		"jsonpath={.items[0].spec.containers[?(@.name=='security-profiles-operator')]"+
			".env[?(@.name=='SPO_PROFILING_PORT')].value}")
	profilingEndpoint := "http://" + podIP + ":" + podPort + "/debug/pprof/heap"

	profilingCurlCMD := curlHTTPVerCMD + profilingEndpoint

	output := e.runAndRetryPodCMD(profilingCurlCMD)
	e.Contains(output, "HTTP/1.1")
}
