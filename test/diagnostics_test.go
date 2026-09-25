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
	"strings"
	"time"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// diagnosticsBeforeDeadline is how long before the test binary times out
	// the diagnostics are dumped, as a timeout skips all cleanups.
	diagnosticsBeforeDeadline = 3 * time.Minute
	// profileDeletionTimeout is how long the per node daemon gets to remove
	// the finalizers of the deleted profiles.
	profileDeletionTimeout = 2 * time.Minute
	// diagnosticsRequestTimeout bounds each request of the diagnostics.
	diagnosticsRequestTimeout = "30s"
)

// profileKinds are the kinds of profiles the per node daemon keeps a finalizer
// on.
var profileKinds = []string{"seccompprofiles", "selinuxprofiles", "apparmorprofiles"}

// BeforeTest dumps the diagnostics shortly before the test binary times out.
func (e *e2e) BeforeTest(_, _ string) {
	e.testStart = time.Now()

	deadline, ok := e.T().Deadline()
	if !ok || time.Until(deadline) <= diagnosticsBeforeDeadline {
		return
	}

	e.diagnosticsTimer = time.AfterFunc(
		time.Until(deadline)-diagnosticsBeforeDeadline,
		func() {
			e.logf("Test is about to time out")
			e.dumpDiagnostics(e.testStart)
		},
	)
}

// AfterTest dumps the diagnostics of a failed test.
func (e *e2e) AfterTest(_, _ string) {
	if e.diagnosticsTimer != nil {
		e.diagnosticsTimer.Stop()
	}

	if e.T().Failed() {
		e.dumpDiagnostics(e.testStart)
	}
}

// SetupSubTest records when the sub test started, for the diagnostics.
func (e *e2e) SetupSubTest() {
	e.subTestStart = time.Now()
}

// TearDownSubTest dumps the diagnostics of a failed sub test.
func (e *e2e) TearDownSubTest() {
	if e.T().Failed() {
		e.dumpDiagnostics(e.subTestStart)
	}
}

// dumpDiagnostics logs the state of the operator and the logs of its pods
// since the given time. It never fails the test, as the cluster may be
// broken.
func (e *e2e) dumpDiagnostics(since time.Time) {
	e.logf("#### Diagnostics ####")
	defer e.logf("#### End of diagnostics ####")

	e.logDiagnostic("-n", config.OperatorName, "get", "pods", "-o", "wide")

	pods, err := e.kubectlCommand(
		"--request-timeout", diagnosticsRequestTimeout,
		"-n", config.OperatorName, "get", "pods", "-o", "name",
	)
	if err != nil {
		e.logf("Unable to list the operator pods: %v", err)
	}

	for pod := range strings.FieldsSeq(pods) {
		e.logDiagnostic(
			"-n", config.OperatorName, "logs", pod, "--all-containers", "--prefix",
			"--since-time="+since.Format(time.RFC3339),
		)
		// Only there if a container restarted.
		e.logDiagnostic(
			"-n", config.OperatorName, "logs", pod, "--all-containers", "--prefix", "--previous",
		)
	}

	for _, kind := range profileKinds {
		e.logDiagnostic("get", kind, "--all-namespaces", "-o", "yaml")
	}
}

// logDiagnostic logs the output of a kubectl command, or why it failed.
func (e *e2e) logDiagnostic(args ...string) {
	output, err := e.kubectlCommand(
		append([]string{"--request-timeout", diagnosticsRequestTimeout}, args...)...,
	)
	if err != nil {
		e.logf("kubectl %s: %v", strings.Join(args, " "), err)

		return
	}

	e.logf("kubectl %s:\n%s", strings.Join(args, " "), output)
}

// cleanupOperator deletes all profiles and the operator. The per node daemon
// removes the finalizers of the profiles, but it may be broken or gone after a
// failed test, so the finalizers left after a while are removed.
func (e *e2e) cleanupOperator(manifest string) {
	e.logf("Cleaning up operator")

	for _, kind := range profileKinds {
		e.kubectl("delete", kind, "--all", "--all-namespaces", "--ignore-not-found", "--wait=false")
	}

	if !e.waitForProfilesDeleted(profileDeletionTimeout) {
		e.dumpDiagnostics(e.testStart)
		e.removeProfileFinalizers()
	}

	e.kubectl("delete", "--ignore-not-found", "--timeout", defaultLongOpTimeout, "-f", manifest)
}

// remainingProfiles returns the profiles which still exist, as their kind,
// name and finalizers separated by "|".
func (e *e2e) remainingProfiles() []string {
	var remaining []string

	for _, kind := range profileKinds {
		output, err := e.kubectlCommand(
			"get", kind, "--all-namespaces", "--ignore-not-found", "-o",
			`jsonpath={range .items[*]}{.kind}|{.metadata.name}|{.metadata.finalizers}{"\n"}{end}`,
		)
		if err != nil {
			// The kind may not be installed.
			continue
		}

		for line := range strings.Lines(output) {
			if line = strings.TrimSpace(line); line != "" {
				remaining = append(remaining, line)
			}
		}
	}

	return remaining
}

// waitForProfilesDeleted reports whether all profiles are gone within the
// timeout.
func (e *e2e) waitForProfilesDeleted(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for {
		remaining := e.remainingProfiles()
		if len(remaining) == 0 {
			return true
		}

		if time.Now().After(deadline) {
			e.logf("Profiles not deleted after %s: %v", timeout, remaining)

			return false
		}

		time.Sleep(defaultWaitTime)
	}
}

// removeProfileFinalizers removes the finalizers of all remaining profiles.
func (e *e2e) removeProfileFinalizers() {
	for _, profile := range e.remainingProfiles() {
		fields := strings.Split(profile, "|")
		if len(fields) < 2 {
			continue
		}

		e.logf("Removing the finalizers of %s", profile)
		e.kubectl(
			"patch", strings.ToLower(fields[0]), fields[1],
			"--type=merge", "-p", `{"metadata":{"finalizers":null}}`,
		)
	}
}
