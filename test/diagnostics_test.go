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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	// journalLines bounds the lines of each node journal in the diagnostics.
	journalLines = "5000"
)

// unsafePathChars are the characters which do not go into the directory name
// of the diagnostics of a test.
var unsafePathChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

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

// The diagnostics are world readable, since the VM jobs write them as root
// and copy them out of the VM as an unprivileged user. They get chmodded, so
// that a stricter umask does not apply.
const (
	diagnosticsDirMode  os.FileMode = 0o755
	diagnosticsFileMode os.FileMode = 0o644
)

// diagnostics collects the diagnostics of a test. They are written to a
// directory per test below E2E_ARTIFACTS_DIR, or logged if it is not set.
type diagnostics struct {
	e *e2e
	// dir is where the diagnostics are written to, empty to log them.
	dir string
}

// newDiagnostics returns the diagnostics of the current test. The directory
// gets a number appended if it exists already, since a test can dump its
// diagnostics more than once.
func (e *e2e) newDiagnostics() *diagnostics {
	d := &diagnostics{e: e}
	if e.artifactsDir == "" {
		return d
	}

	base := filepath.Join(e.artifactsDir, unsafePathChars.ReplaceAllString(e.T().Name(), "_"))
	dir := base

	for i := 2; ; i++ {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			break
		}

		dir = fmt.Sprintf("%s-%d", base, i)
	}

	if err := os.MkdirAll(dir, diagnosticsDirMode); err != nil {
		e.logf("Unable to create the diagnostics directory, logging them instead: %v", err)

		return d
	}

	for _, path := range []string{e.artifactsDir, dir} {
		if err := os.Chmod(path, diagnosticsDirMode); err != nil {
			e.logf("Unable to make %s readable: %v", path, err)
		}
	}

	e.logf("Writing the diagnostics to %s", dir)
	d.dir = dir

	return d
}

// add writes the output of a diagnostic, or why it could not be collected.
func (d *diagnostics) add(name, description, output string, err error) {
	if err != nil {
		output = fmt.Sprintf("%s\nfailed: %v", output, err)
	}

	if d.dir == "" {
		d.e.logf("%s:\n%s", description, output)

		return
	}

	content := fmt.Sprintf("# %s\n%s\n", description, output)

	path := filepath.Join(d.dir, unsafePathChars.ReplaceAllString(name, "_")+".txt")
	if writeErr := os.WriteFile(path, []byte(content), diagnosticsFileMode); writeErr != nil {
		d.e.logf("Unable to write %s: %v\n%s", path, writeErr, content)

		return
	}

	if err := os.Chmod(path, diagnosticsFileMode); err != nil {
		d.e.logf("Unable to make %s readable: %v", path, err)
	}
}

// kubectl adds the output of a kubectl command.
func (d *diagnostics) kubectl(name string, args ...string) {
	output, err := d.e.kubectlCommand(
		append([]string{"--request-timeout", diagnosticsRequestTimeout}, args...)...,
	)
	d.add(name, "kubectl "+strings.Join(args, " "), output, err)
}

// dumpDiagnostics collects the state of the cluster and the operator, and the
// logs of its pods and the nodes since the given time. It never fails the
// test, as the cluster may be broken.
func (e *e2e) dumpDiagnostics(since time.Time) {
	e.logf("#### Diagnostics ####")
	defer e.logf("#### End of diagnostics ####")

	d := e.newDiagnostics()

	d.kubectl("pods", "-n", config.OperatorName, "get", "pods", "-o", "wide")
	d.kubectl("describe-pods", "-n", config.OperatorName, "describe", "pods")
	d.kubectl("events", "get", "events", "--all-namespaces", "--sort-by=.lastTimestamp")
	d.kubectl("spod", "-n", config.OperatorName, "get", "spod", "spod", "-o", "yaml")
	d.kubectl(
		"webhook-configurations", "get",
		"mutatingwebhookconfigurations,validatingwebhookconfigurations", "-o", "yaml",
	)

	pods, err := e.kubectlCommand(
		"--request-timeout", diagnosticsRequestTimeout,
		"-n", config.OperatorName, "get", "pods", "-o", "name",
	)
	if err != nil {
		e.logf("Unable to list the operator pods: %v", err)
	}

	for pod := range strings.FieldsSeq(pods) {
		name := strings.TrimPrefix(pod, "pod/")
		d.kubectl(
			"logs-"+name, "-n", config.OperatorName, "logs", pod, "--all-containers", "--prefix",
			"--since-time="+since.Format(time.RFC3339),
		)
		// Only there if a container restarted.
		d.kubectl(
			"logs-previous-"+name,
			"-n", config.OperatorName, "logs", pod, "--all-containers", "--prefix", "--previous",
		)
	}

	for _, kind := range profileKinds {
		d.kubectl(kind, "get", kind, "--all-namespaces", "-o", "yaml")
	}

	e.dumpNodeJournals(d, since)
}

// dumpNodeJournals adds the journals of the container runtime and the kubelet
// of all nodes since the given time. The units which do not exist on a node
// have no entries.
func (e *e2e) dumpNodeJournals(d *diagnostics, since time.Time) {
	if e.nodeCommand == nil {
		return
	}

	nodes, err := e.kubectlCommand(
		"--request-timeout", diagnosticsRequestTimeout,
		"get", "nodes", "-o", `jsonpath={range .items[*]}{.metadata.name}{" "}{end}`,
	)
	if err != nil {
		e.logf("Unable to list the nodes: %v", err)

		return
	}

	for node := range strings.FieldsSeq(nodes) {
		args := []string{
			"journalctl", "--no-pager", "--lines", journalLines,
			"--since", "@" + strconv.FormatInt(since.Unix(), 10),
			"-u", "crio", "-u", "containerd", "-u", "kubelet",
		}
		output, err := e.nodeCommand(node, args...)
		d.add("journal-"+node, "node "+node+": "+strings.Join(args, " "), output, err)
	}
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

	e.kubectl(
		"delete", "--ignore-not-found", "--timeout", defaultLongOpTimeout,
		"-f", e.renderedManifest(manifest),
	)
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
	err := poll(timeout, defaultWaitTime, func() error {
		if remaining := e.remainingProfiles(); len(remaining) > 0 {
			return fmt.Errorf("profiles not deleted: %v", remaining)
		}

		return nil
	})
	if err != nil {
		e.logf("%v", err)

		return false
	}

	return true
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
