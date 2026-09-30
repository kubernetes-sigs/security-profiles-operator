//go:build e2e

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

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

const (
	profileName = "metrics-profile"
	// metricsTimeout is how long the daemons get to count an operation.
	metricsTimeout = 2 * time.Minute
)

// scrapeSpodMetrics returns the metrics of the daemons on all nodes. The
// metrics service picks one daemon per request, so each daemon gets scraped
// through the IP of its pod instead.
func (e *e2e) scrapeSpodMetrics() string {
	podIPs := strings.Fields(e.kubectlOperatorNS(
		"get", "pods", "-l", "name=spod", "-o", "jsonpath={.items[*].status.podIP}",
	))
	e.Require().NotEmpty(podIPs, "no IPs of the spod pods")

	// The service has only one daemon to pick then. Pods cannot connect to
	// the IP of another pod on every CI cluster, like on kubernix on the
	// GitHub runners, while the service works there.
	if len(podIPs) == 1 {
		return e.runAndRetryPodCMD(curlSpodCMD)
	}

	urls := make([]string, 0, len(podIPs))
	for _, ip := range podIPs {
		urls = append(urls, "https://"+
			net.JoinHostPort(ip, strconv.Itoa(int(bindata.ContainerPort)))+metrics.HandlerPath)
	}

	return e.runAndRetryPodCMD(curlCMD + strings.Join(urls, " "))
}

// waitForMetricsIncrease waits until the daemons of all nodes counted more
// updates and deletions than before.
func (e *e2e) waitForMetricsIncrease(
	operationUpdate, operationDelete string, updates, deletions int,
) {
	e.eventually(metricsTimeout, defaultPollInterval, func() error {
		output := e.scrapeSpodMetrics()
		if !strings.Contains(output, "promhttp_metric_handler_requests_total") {
			return fmt.Errorf("no metrics of the daemons: %s", output)
		}

		newUpdates := e.parseMetric(output, operationUpdate)
		newDeletions := e.parseMetric(output, operationDelete)

		if newUpdates <= updates || newDeletions <= deletions {
			return fmt.Errorf(
				"updates went from %d to %d, deletions from %d to %d",
				updates, newUpdates, deletions, newDeletions,
			)
		}

		return nil
	})
}

func (e *e2e) testCaseSeccompMetrics([]string) {
	e.seccompOnlyTestCase()

	const (
		operationDelete = `security_profiles_operator_seccomp_profile_total{operation="delete"}`
		operationUpdate = `security_profiles_operator_seccomp_profile_total{operation="update"}`
	)

	e.logf("Retrieving spo metrics for getting assertions")
	output := e.scrapeSpodMetrics()
	metricDeletions := e.parseMetric(output, operationDelete)
	metricUpdates := e.parseMetric(output, operationUpdate)

	profile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: "SCMP_ACT_ALLOW"
`, profileName)

	e.logf("Creating test profile")

	e.writeAndCreate(profile, "metrics-profile*.yaml")

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Deleting test profile")
	e.kubectl("delete", "sp", profileName)

	e.logf("Retrieving controller runtime metrics")
	e.kubectlRunOperatorNS("pod-2", "--", "bash", "-c", curlCtrlCMD)

	e.logf("Asserting that the daemons counted the update and the deletion")
	e.waitForMetricsIncrease(operationUpdate, operationDelete, metricUpdates, metricDeletions)
}

func (e *e2e) testCaseSelinuxMetrics(nodes []string) {
	e.selinuxOnlyTestCase()

	const (
		operationDelete = `security_profiles_operator_selinux_profile_total{operation="delete"}`
		operationUpdate = `security_profiles_operator_selinux_profile_total{operation="update"}`
	)

	e.logf("Retrieving spo metrics for getting assertions")
	output := e.scrapeSpodMetrics()
	metricDeletions := e.parseMetric(output, operationDelete)
	metricUpdates := e.parseMetric(output, operationUpdate)

	e.logf("Creating test errorlogger policy")

	e.writeAndCreate(errorloggerPolicy, "errorlogger-policy.yml")

	e.logf("Waiting for profile to be reconciled")
	e.kubectl("wait", "--timeout", defaultLongOpTimeout,
		"--for", "condition=ready", "selinuxprofile", "errorlogger")

	rawPolicyName := e.getSELinuxPolicyName("selinuxprofile", "errorlogger")
	e.logf("assert errorlogger policy is installed")
	e.assertSelinuxPolicyIsInstalled(nodes, rawPolicyName)

	e.logf("Deleting errorlogger profile")
	e.kubectl("delete", "selinuxprofile", "errorlogger")
	e.logf("assert errorlogger policy was removed")
	e.assertSelinuxPolicyIsRemoved(nodes, rawPolicyName)

	e.logf("Asserting that the daemons counted the update and the deletion")
	e.waitForMetricsIncrease(operationUpdate, operationDelete, metricUpdates, metricDeletions)
}

// parseMetric returns the sum of the values of the metric in the content,
// which has the metrics of all daemons.
func (e *e2e) parseMetric(content, metric string) int {
	sum := 0

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, metric) {
			fields := strings.Fields(line)
			e.Len(fields, 2)
			i, err := strconv.Atoi(fields[1])
			e.NoError(err)

			sum += i
		}
	}

	return sum
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
