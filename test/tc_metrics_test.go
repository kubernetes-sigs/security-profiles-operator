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
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

const profileName = "metrics-profile"

func (e *e2e) testCaseSeccompMetrics([]string) {
	e.seccompOnlyTestCase()
	e.singleNodeTestCase()

	const (
		operationDelete = `security_profiles_operator_seccomp_profile_total{operation="delete"}`
		operationUpdate = `security_profiles_operator_seccomp_profile_total{operation="update"}`
	)

	e.logf("Retrieving spo metrics for getting assertions")
	output := e.runAndRetryPodCMD(curlSpodCMD)
	metricDeletions := e.parseMetric(output, operationDelete)
	metricUpdates := e.parseMetric(output, operationUpdate)

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: "SCMP_ACT_ALLOW"
`, profileName)

	e.logf("Creating test profile")

	cleanup := e.writeAndCreate(profile, "metrics-profile*.yaml")
	defer cleanup()
	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Deleting test profile")
	e.kubectl("delete", "sp", profileName)

	e.logf("Retrieving controller runtime metrics")
	e.kubectlRunOperatorNS("pod-2", "--", "bash", "-c", curlCtrlCMD)

	e.logf("Retrieving spo metrics for validation")
	outputSpod := e.runAndRetryPodCMD(curlSpodCMD)
	e.Contains(outputSpod, "promhttp_metric_handler_requests_total")

	e.logf("Asserting metrics values")
	newMetricDeletions := e.parseMetric(outputSpod, operationDelete)
	newMetricUpdates := e.parseMetric(outputSpod, operationUpdate)
	e.GreaterOrEqual(newMetricDeletions, metricDeletions)
	e.GreaterOrEqual(newMetricUpdates, metricUpdates)
}

func (e *e2e) testCaseSelinuxMetrics(nodes []string) {
	e.selinuxOnlyTestCase()
	e.singleNodeTestCase()

	const (
		operationDelete = `security_profiles_operator_selinux_profile_total{operation="delete"}`
		operationUpdate = `security_profiles_operator_selinux_profile_total{operation="update"}`
	)

	e.logf("Retrieving spo metrics for getting assertions")
	output := e.kubectlRunOperatorNS("pod", "--", "bash", "-c", curlSpodCMD)
	metricDeletions := e.parseMetric(output, operationDelete)
	metricUpdates := e.parseMetric(output, operationUpdate)

	e.logf("Creating test errorlogger policy")

	cleanup := e.writeAndCreate(errorloggerPolicy, "errorlogger-policy.yml")
	defer cleanup()
	e.logf("Waiting for profile to be reconciled")
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxprofile", "errorlogger")

	rawPolicyName := e.getSELinuxPolicyName("selinuxprofile", "errorlogger")
	e.logf("assert errorlogger policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)

	e.logf("Deleting errorlogger profile")
	e.kubectl("delete", "selinuxprofile", "errorlogger")
	e.logf("assert errorlogger policy was removed")
	e.assertSelinuxPolicyIsRemoved(nodes, rawPolicyName, maxNodeIterations, sleepBetweenIterations)

	e.logf("Retrieving spo metrics for validation")
	outputSpod := e.runAndRetryPodCMD(curlSpodCMD)
	e.Contains(outputSpod, "promhttp_metric_handler_requests_total")

	e.logf("Asserting metrics values")
	newMetricDeletions := e.parseMetric(outputSpod, operationDelete)
	newMetricUpdates := e.parseMetric(outputSpod, operationUpdate)
	e.GreaterOrEqual(newMetricDeletions, metricDeletions)
	e.GreaterOrEqual(newMetricUpdates, metricUpdates)
}

func (e *e2e) parseMetric(content, metric string) int {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, metric) {
			fields := strings.Fields(line)
			e.Len(fields, 2)
			i, err := strconv.Atoi(fields[1])
			e.Nil(err)

			return i
		}
	}

	return 0
}

func (e *e2e) testCaseMetricsHTTP([]string) {
	if !e.testMetricsHTTP {
		e.T().Skip("Skipping metrics HTTP version related tests")
	}

	e.logf("Test metrics HTTP version")

	endpoints := []string{
		curlHTTPVerCMD + metricsURL + "metrics",
		curlHTTPVerCMD + metricsURL + "metrics-spod",
	}
	for _, endpoint := range endpoints {
		output := e.runAndRetryPodCMD(endpoint)
		e.Contains(output, "1.1\n")
	}
}
