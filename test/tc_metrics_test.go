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

func (e *e2e) testCaseMetrics(nodes []string) {
	e.seccompOnlyTestCase()

	const (
		curlCMD         = "curl -ks -H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" "
		metricsURL      = "https://metrics/"
		curlSpodCMD     = curlCMD + metricsURL + "metrics-spod"
		curlCtrlCMD     = curlCMD + metricsURL + "metrics"
		profileName     = "metrics-profile"
		operationDelete = `security_profiles_operator_seccomp_profile{operation="delete"}`
		operationUpdate = `security_profiles_operator_seccomp_profile{operation="update"}`
	)

	e.logf("Retrieving spo metrics for getting assertions")
	output := e.kubectlRunOperatorNS("pod", "--", "bash", "-c", curlSpodCMD)
	metricDeletions := e.parseMetric(output, operationDelete)
	metricUpdates := e.parseMetric(output, operationUpdate)

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
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
	e.waitFor("condition=ready", "sp", profileName)

	e.logf("Deleting test profile")
	e.kubectl("delete", "sp", profileName, "--wait=0")

	e.logf("Retrieving controller runtime metrics")
	outputCtrl := e.kubectlRunOperatorNS("pod", "--", "bash", "-c", curlCtrlCMD)
	e.Contains(outputCtrl, "workqueue_work_duration_seconds_count")

	e.logf("Retrieving spo metrics for validation")
	outputSpod := e.kubectlRunOperatorNS("pod", "--", "bash", "-c", curlSpodCMD)
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
