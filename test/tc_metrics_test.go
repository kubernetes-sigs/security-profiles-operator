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
	"maps"
	"net"
	"slices"
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

// scrapeSeparator is what curl prints after the metrics of each daemon,
// followed by the URL it scraped them from.
const scrapeSeparator = "# end of the metrics of "

// scrapeSpodMetrics returns the metrics of the daemons on all nodes.
func (e *e2e) scrapeSpodMetrics() string {
	return strings.Join(slices.Collect(maps.Values(e.scrapeSpodMetricsByDaemon())), "\n")
}

// scrapeSpodMetricsByDaemon returns the metrics of the daemon on each node,
// keyed by the name of its spod pod. The metrics service picks one daemon per
// request, so each daemon gets scraped through the IP of its pod instead. A
// daemon without an IP or without output has empty metrics, so that a check of
// all daemons notices it.
func (e *e2e) scrapeSpodMetricsByDaemon() map[string]string {
	pods := strings.Split(strings.TrimSpace(e.kubectlOperatorNS(
		"get", "pods", "-l", "name=spod", "-o",
		`jsonpath={range .items[*]}{.metadata.name}{" "}{.status.podIP}{"\n"}{end}`,
	)), "\n")

	byDaemon := make(map[string]string, len(pods))
	podsByURL := make(map[string]string, len(pods))

	for _, pod := range pods {
		name, ip, _ := strings.Cut(strings.TrimSpace(pod), " ")
		if name == "" {
			continue
		}

		byDaemon[name] = ""

		if ip != "" {
			podsByURL["https://"+net.JoinHostPort(ip, strconv.Itoa(int(bindata.ContainerPort)))+
				metrics.HandlerPath] = name
		}
	}

	e.Require().NotEmpty(byDaemon, "no spod pods")

	// The service has only one daemon to pick then. Pods cannot connect to
	// the IP of another pod on every CI cluster, like on kubernix on the
	// GitHub runners, while the service works there.
	if len(byDaemon) == 1 {
		for name := range byDaemon {
			byDaemon[name] = e.runAndRetryPodCMD(curlSpodCMD)
		}

		return byDaemon
	}

	if len(podsByURL) == 0 {
		return byDaemon
	}

	output := e.runAndRetryPodCMD(
		curlCMD + `-w '\n` + scrapeSeparator + `%{url_effective}\n' ` +
			strings.Join(slices.Sorted(maps.Keys(podsByURL)), " "),
	)

	var content []string

	for line := range strings.Lines(output) {
		url, found := strings.CutPrefix(strings.TrimSpace(line), scrapeSeparator)
		if !found {
			content = append(content, line)

			continue
		}

		if name, ok := podsByURL[url]; ok {
			byDaemon[name] = strings.Join(content, "")
		}

		content = nil
	}

	return byDaemon
}

// metricCounts are the update and deletion counts of each daemon.
type metricCounts map[string][2]int

// countMetrics returns the update and deletion counts of each daemon, and an
// error which names the daemons whose metrics are missing.
func (e *e2e) countMetrics(operationUpdate, operationDelete string) (metricCounts, error) {
	counts := metricCounts{}

	var missing []string

	for daemon, output := range e.scrapeSpodMetricsByDaemon() {
		if !strings.Contains(output, "promhttp_metric_handler_requests_total") {
			missing = append(missing, daemon)

			continue
		}

		counts[daemon] = [2]int{
			e.parseMetric(output, operationUpdate),
			e.parseMetric(output, operationDelete),
		}
	}

	if len(missing) > 0 {
		return counts, fmt.Errorf("no metrics of the daemons %v", missing)
	}

	return counts, nil
}

// baselineMetrics returns the update and deletion counts of each daemon, and
// retries until it gets the metrics of all daemons.
func (e *e2e) baselineMetrics(operationUpdate, operationDelete string) metricCounts {
	var counts metricCounts

	err := poll(metricsTimeout, defaultPollInterval, func() (err error) {
		counts, err = e.countMetrics(operationUpdate, operationDelete)

		return err
	})
	e.Require().NoError(err, "metrics of all daemons before the test")

	return counts
}

// waitForMetricsIncrease waits until the daemon of each node counted more
// updates and deletions than before. A daemon of a spod pod which replaced
// one of before starts at zero.
func (e *e2e) waitForMetricsIncrease(
	operationUpdate, operationDelete string, before metricCounts,
) {
	e.eventually(metricsTimeout, defaultPollInterval, func() error {
		after, err := e.countMetrics(operationUpdate, operationDelete)
		if err != nil {
			return err
		}

		for daemon, counts := range after {
			if counts[0] <= before[daemon][0] || counts[1] <= before[daemon][1] {
				return fmt.Errorf(
					"daemon %s: updates went from %d to %d, deletions from %d to %d",
					daemon, before[daemon][0], counts[0], before[daemon][1], counts[1],
				)
			}
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
	before := e.baselineMetrics(operationUpdate, operationDelete)

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
	e.kubectlCleanup("sp", profileName)

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	e.logf("Deleting test profile")
	e.kubectl("delete", "sp", profileName)

	e.logf("Retrieving controller runtime metrics")
	// The daemons just reconciled the profile.
	e.Contains(e.runAndRetryPodCMD(curlCtrlCMD), "controller_runtime_reconcile_total")

	e.logf("Asserting that the daemons counted the update and the deletion")
	e.waitForMetricsIncrease(operationUpdate, operationDelete, before)
}

func (e *e2e) testCaseSelinuxMetrics(nodes []string) {
	e.selinuxOnlyTestCase()

	const (
		operationDelete = `security_profiles_operator_selinux_profile_total{operation="delete"}`
		operationUpdate = `security_profiles_operator_selinux_profile_total{operation="update"}`
	)

	e.logf("Retrieving spo metrics for getting assertions")
	before := e.baselineMetrics(operationUpdate, operationDelete)

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
	e.waitForMetricsIncrease(operationUpdate, operationDelete, before)
}

// parseMetric returns the sum of the values of the metric in the content.
func (e *e2e) parseMetric(content, metric string) int {
	sum := 0

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, metric) {
			fields := strings.Fields(line)
			e.Require().Len(fields, 2, "metric line %q", line)
			i, err := strconv.Atoi(fields[1])
			e.Require().NoError(err, "metric line %q", line)

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
		e.assertHTTP11(output)
	}
}
