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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	certmanager = "https://github.com/cert-manager/cert-manager/releases/download/v1.21.3/cert-manager.yaml"
	// certmanagerSHA256 is the checksum of certmanager, bump it together with
	// the version, see dependencies.yaml.
	certmanagerSHA256    = "c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74"
	namespaceManifest    = "deploy/namespace-operator.yaml"
	testNamespace        = "test-ns"
	defaultNamespace     = "default"
	defaultLongOpTimeout = "360s"
	defaultWaitTimeout   = "5m"
	defaultWaitTime      = 15 * time.Second
	// defaultWaitDuration mirrors defaultWaitTimeout for waits done in Go
	// rather than handed to kubectl.
	defaultWaitDuration = 5 * time.Minute
	// defaultPollInterval is how often the waits done in Go check again.
	defaultPollInterval = 3 * time.Second
	// statusUpdateTimeout is how long the controllers get to update the
	// status or the finalizers of an object after a workload changed.
	statusUpdateTimeout = time.Minute
	// podCommandTimeout is how long a command run in a throwaway pod gets
	// retried until it succeeds.
	podCommandTimeout = 2 * time.Minute
	// absentProfileTimeout is how long a profile which must not get recorded
	// has to stay absent after the other profiles of the pod got recorded.
	absentProfileTimeout = 30 * time.Second

	// podStartTimeout is how long a pod of the operator gets to start.
	podStartTimeout = 25 * time.Second

	// execEnvironmentTimeout is how long a pod gets to run and accept an exec
	// with the environment of the exec metadata webhook.
	execEnvironmentTimeout = 100 * time.Second
	// spodGenerationTimeout is how long a SPOD change gets to show up as a
	// new generation of the spod daemon set.
	spodGenerationTimeout = 15 * time.Second
	// renderedManifestsDir is where the suite writes the manifests it
	// deploys, so that the tracked ones stay untouched.
	renderedManifestsDir = "build/e2e-manifests"
	// reDeployDescription is the description of the test case which gets
	// replaced for the namespaced operator.
	reDeployDescription = "Seccomp: Re-deploy the operator"
)

// testCase is an end-to-end test case. Each test case cleans up on its own
// and leaves a working operator behind.
//
// Flaky test cases are quarantined: TestSecurityProfilesOperator_Flaky runs
// them, and make test-flaky-e2e retries them once when they fail, while
// TestSecurityProfilesOperator runs all others. A test case gets quarantined
// or promoted by flipping flaky, see doc/hacking.md.
type testCase struct {
	description string
	fn          func(nodes []string)
	// flaky quarantines the test case.
	flaky bool
	// issue says why the test case is quarantined, ideally the link of the
	// issue which tracks it.
	issue string
	// clusterWideOnly skips the test case for the namespaced operator.
	clusterWideOnly bool
}

// testCases returns all test cases in the order they run.
func (e *e2e) testCases() []testCase {
	return []testCase{
		{
			description: "Seccomp: Verify default and example profiles",
			fn:          e.testCaseDefaultAndExampleProfiles,
		},
		{
			description: "Seccomp: Verify base profile merge",
			fn:          e.testCaseBaseProfile,
		},
		{
			description: "Seccomp: Verify runtime format OCI base profile",
			fn:          e.testCaseBaseProfileOCIRuntimeFormat,
		},
		{
			description: "Seccomp: Allowed syscalls",
			fn:          e.testCaseAllowedSyscalls,
		},
		{
			description: "Seccomp: Delete profiles",
			fn:          e.testCaseDeleteProfiles,
		},
		{
			description: reDeployDescription,
			fn:          e.testCaseReDeployOperator,
		},
		{
			description: "Log Enricher",
			fn:          e.testCaseLogEnricher,
		},
		{
			description: "Log Enricher (BPF Source)",
			fn:          e.testCaseLogEnricherBpf,
			flaky:       true,
			issue:       bpfEnricherIssue,
		},
		{
			description: "JSON Enricher",
			fn:          e.testCaseJsonEnricher,
		},
		{
			description: "Log Enricher with filters",
			fn:          e.testCaseLogEnricherWithFilters,
		},
		{
			description: "JSON Enricher File Options",
			fn:          e.testCaseJsonEnricherFileOptions,
		},
		{
			description: "SELinux: base case (install policy, run pod and delete)",
			fn:          e.testCaseSelinuxBaseUsage,
		},
		{
			description: "SELinux: base case (install policy, run pod and delete) for the raw CR",
			fn:          e.testCaseRawSelinuxBaseUsage,
		},
		{
			description: "SELinux: non-default template",
			fn:          e.testCaseSelinuxNonDefaultTemplate,
		},
		{
			description: "SELinux: Metrics (update, delete)",
			fn:          e.testCaseSelinuxMetrics,
			flaky:       true,
			issue:       nodeAwareMetricsIssue,
		},
		{
			description: "SPOD: Update SELinux flag",
			fn:          e.testCaseSPODUpdateSelinux,
		},
		{
			description: "SPOD: Change verbosity",
			fn:          e.testCaseVerbosityChange,
		},
		{
			description: "SPOD: Change profiling",
			fn:          e.testCaseProfilingChange,
		},
		{
			description: "SPOD: Profiling server protocol",
			fn:          e.testCaseProfilingHTTP,
		},
		{
			description: "SPOD: Enable memory optimization",
			fn:          e.testCaseMemOptmEnable,
		},
		{
			description: "SPOD: Change resource requirements",
			fn:          e.testCaseResourceRequirementsChange,
		},
		{
			description: "Seccomp: make sure statuses for profiles with long names can be listed",
			fn:          e.testCaseLongSeccompProfileName,
		},
		{
			description: "SPOD: Change webhook config",
			fn:          e.testCaseWebhookOptionsChange,
		},
		{
			description: "SPOD: Enable profile recorder",
			fn:          e.testCaseSPODEnableProfileRecorder,
		},
		{
			description: "TLS: Verify TLS profile on OpenShift",
			fn:          e.testCaseTLSProfileOpenShift,
		},
		{
			description:     "Selinux: Verify profile binding: image",
			fn:              func([]string) { e.testCaseSelinuxProfileBinding(busyboxImage) },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify profile binding: wildcard",
			fn:              func([]string) { e.testCaseSelinuxProfileBinding("'*'") },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify profile binding: namespace not enabled",
			fn:              func([]string) { e.testCaseSelinuxProfileBindingNsNotEnabled() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify the policy can be marked as permissive: enforcing",
			fn:              func([]string) { e.testCaseSelinuxIncompletePolicy() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify the policy can be marked as permissive: permissive",
			fn:              func([]string) { e.testCaseSelinuxIncompletePermissivePolicy() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify that the SPOD can deny permissive policies",
			fn:              e.testCaseSelinuxDeniedPermissivePolicy,
			clusterWideOnly: true,
			flaky:           true,
			issue:           newTestCaseIssue,
		},
		{
			description:     "Selinux: Verify the policy can be marked as permissive: disabled",
			fn:              func([]string) { e.testCaseSelinuxIncompleteDisabledPolicy() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify SELinux profile recording logs: static pod",
			fn:              func([]string) { e.testCaseProfileRecordingStaticPodSELinuxLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify SELinux profile recording logs: multiple containers",
			fn:              func([]string) { e.testCaseProfileRecordingMultiContainerSELinuxLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify SELinux profile recording logs: deployment",
			fn:              func([]string) { e.testCaseProfileRecordingSelinuxDeploymentLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Selinux: Verify SELinux profile recording logs: namespace not enabled",
			fn:              func([]string) { e.testCaseProfileRecordingStaticPodSELinuxLogsNsNotEnabled() },
			clusterWideOnly: true,
		},
		{
			description:     "profile merging: seccomp bpf",
			fn:              func([]string) { e.testSeccompBpfProfileMerging() },
			clusterWideOnly: true,
		},
		{
			description:     "profile merging: seccomp logs",
			fn:              func([]string) { e.testSeccompLogsProfileMerging() },
			clusterWideOnly: true,
		},
		{
			description:     "profile merging: selinux logs",
			fn:              func([]string) { e.testSelinuxLogsProfileMerging() },
			clusterWideOnly: true,
		},
		{
			description:     "profile merging: selinux logs disabled",
			fn:              func([]string) { e.testSelinuxLogsDisabledProfileMerging() },
			clusterWideOnly: true,
		},
		{
			description: "Seccomp: Metrics",
			fn:          e.testCaseSeccompMetrics,
		},
		{
			description: "SPOD: Test webhook HTTP version",
			fn:          e.testCaseWebhookHTTP,
		},
		{
			description: "SPOD: Test Metrics HTTP version",
			fn:          e.testCaseMetricsHTTP,
			flaky:       true,
			issue:       untrackedIssue,
		},
		{
			description: "Seccomp: Verify profile binding: image",
			fn: func(nodes []string) {
				e.testCaseSeccompProfileBinding(nodes, busyboxImage)
			},
			flaky:           true,
			issue:           inUseFinalizerIssue,
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile binding: wildcard",
			fn:              func(nodes []string) { e.testCaseSeccompProfileBinding(nodes, "'*'") },
			flaky:           true,
			issue:           bindingIssue,
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: static pod",
			fn:              func([]string) { e.testCaseProfileRecordingStaticPodLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: multiple containers",
			fn:              func([]string) { e.testCaseProfileRecordingMultiContainerLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: specific container",
			fn:              func([]string) { e.testCaseProfileRecordingSpecificContainerLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: deployment",
			fn:              func([]string) { e.testCaseProfileRecordingDeploymentLogs() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: finalizers",
			fn:              func([]string) { e.testCaseRecordingFinalizers() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: deployment scale up and down",
			fn:              func([]string) { e.testCaseProfileRecordingDeploymentScaleUpDownLogs() },
			flaky:           true,
			issue:           untrackedIssue,
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording logs: memory optimization",
			fn:              func([]string) { e.testCaseProfileRecordingWithMemoryOptimization() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: kubectl run",
			fn:              func([]string) { e.testCaseBpfRecorderKubectlRun() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: static pod",
			fn:              func([]string) { e.testCaseBpfRecorderStaticPod() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: multiple containers",
			fn:              func([]string) { e.testCaseBpfRecorderMultiContainer() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: deployment",
			fn:              func([]string) { e.testCaseBpfRecorderDeployment() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: parallel",
			fn:              func([]string) { e.testCaseBpfRecorderParallel() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: select container",
			fn:              func([]string) { e.testCaseBpfRecorderSelectContainer() },
			clusterWideOnly: true,
		},
		{
			description:     "Seccomp: Verify profile recording bpf: memory optimization",
			fn:              func([]string) { e.testCaseBpfRecorderWithMemoryOptimization() },
			clusterWideOnly: true,
		},
		{
			description:     "SPOD: Upgrade from the previous release",
			fn:              e.testCaseUpgradeFromPreviousRelease,
			clusterWideOnly: true,
		},
		{
			description:     "SPOD: Webhook down",
			fn:              e.testCaseWebhookDown,
			clusterWideOnly: true,
		},
	}
}

const (
	// untrackedIssue marks the test cases which were quarantined before the
	// quarantine got tracked per test case.
	untrackedIssue = "quarantined as a group before, no issue filed yet"
	// bindingIssue is why the binding test cases do not run for the
	// namespaced operator.
	bindingIssue = "the webhook certificates of the namespaced operator are not ready in time"
	// inUseFinalizerIssue marks the test cases which wait for the in-use
	// finalizer of a profile, which a conflicting update of the workload
	// annotator can lose.
	inUseFinalizerIssue = "the workload annotator can lose the in-use finalizer on a conflict"
	// nodeAwareMetricsIssue marks the metrics test cases, which only ran on
	// single node clusters before they scraped the daemons of all nodes.
	nodeAwareMetricsIssue = "scrapes the daemons of all nodes now, promote it once it passes reliably in CI"
	// bpfEnricherIssue marks the log enricher test case with the BPF
	// source, which no CI job runs yet, see E2E_TEST_BPF_LOG_ENRICHER in
	// doc/hacking.md. A quarantined case which fails on retry fails the
	// flaky test step, so it gets enabled once it passed on a node.
	bpfEnricherIssue = "needs nodes with AppArmor for its kprobe on aa_audit, not proven in CI yet"
	// newTestCaseIssue marks new test cases, which start quarantined, see
	// doc/hacking.md.
	newTestCaseIssue = "new test case, promote it once it passes reliably in CI"
)

func (e *e2e) TestSecurityProfilesOperator() {
	e.runTestCases()
}

// quarantinedTestName is the name of the suite method which runs the
// quarantined test cases.
const quarantinedTestName = "TestSecurityProfilesOperator_Flaky"

// runsQuarantinedTests reports whether the current suite method runs the
// quarantined test cases.
func (e *e2e) runsQuarantinedTests() bool {
	return strings.HasSuffix(e.T().Name(), "/"+quarantinedTestName)
}

// skipsQuarantinedTests reports whether the current suite method runs the
// quarantined test cases, which E2E_SKIP_FLAKY_TESTS skips. SetupTest uses it
// to not prepare a cluster for nothing.
func (e *e2e) skipsQuarantinedTests() bool {
	return e.skipFlakyTests && e.runsQuarantinedTests()
}

// shardDescription describes the test cases the suite runs, for messages.
func (e *e2e) shardDescription() string {
	if e.shard.total == 0 {
		return "to run"
	}

	return "in shard " + e.shard.String()
}

// shardIsEmpty reports whether the shard of the suite has no test cases of the
// current suite method. SetupTest uses it to not prepare a cluster for
// nothing.
func (e *e2e) shardIsEmpty() bool {
	clusterWide, namespaced := e.shardTestCases()

	return len(clusterWide) == 0 && len(namespaced) == 0
}

func (e *e2e) TestSecurityProfilesOperator_Flaky() {
	if e.skipsQuarantinedTests() {
		e.T().Skip("Skipping the quarantined test cases, E2E_SKIP_FLAKY_TESTS is set")

		return
	}

	// kind starts no cluster for an empty shard, so it gets skipped before
	// the context is reset.
	if e.shardIsEmpty() {
		e.T().Skip("No quarantined test cases " + e.shardDescription())

		return
	}

	// If we ran the non-flaky tests before, we would have ran them with the
	// context set to the test-ns namespace. Reset the context.
	e.kubectl("config", "set-context", "--current", "--namespace", config.OperatorName)

	e.runTestCases()
}

// runTestCases runs the test cases of the current suite method and shard, see
// shardTestCases, against the cluster wide and then the namespaced operator.
func (e *e2e) runTestCases() {
	clusterWide, namespaced := e.shardTestCases()
	if len(clusterWide) == 0 && len(namespaced) == 0 {
		e.T().Skip("No test cases " + e.shardDescription())

		return
	}

	if e.shard.total != 0 {
		e.logf("Running %d cluster wide and %d namespaced test cases of shard %s",
			len(clusterWide), len(namespaced), e.shard)
	}

	e.waitForReadyPods()

	// Deploy prerequisites
	e.deployCertManager()

	// Retrieve the inputs for the test cases
	nodes := e.getNodes()

	if len(clusterWide) > 0 {
		// Deploy the operator
		undeploy := e.deployOperatorWithCleanup(e.operatorManifest)

		e.logf("testing cluster-wide operator")
		e.runTestCasesWithPrefix("cluster-wide", clusterWide, nodes)

		// Clean up cluster-wide deployment to prepare for namespace deployment
		undeploy()
	}

	e.testNamespacedOperator(namespaceManifest, testNamespace, namespaced, nodes)
}

// runTestCasesWithPrefix runs each test case as sub test, named after its
// description with the prefix.
func (e *e2e) runTestCasesWithPrefix(prefix string, testCases []testCase, nodes []string) {
	for _, tc := range testCases {
		e.Run(prefix+": "+tc.description, func() {
			if tc.flaky {
				e.logf("Running quarantined test case: %s", tc.issue)
			}

			tc.fn(nodes)
		})
	}
}

// namespacedTestCases returns the test cases which also run against the
// namespaced operator.
func (e *e2e) namespacedTestCases(testCases []testCase) []testCase {
	namespacedTestCases := make([]testCase, 0, len(testCases))

	for _, tc := range testCases {
		if tc.clusterWideOnly {
			continue
		}

		// Replace re-deploy the operator with a namespaced alternative.
		if tc.description == reDeployDescription {
			tc.fn = e.testCaseReDeployNamespaceOperator
		}

		namespacedTestCases = append(namespacedTestCases, tc)
	}

	return namespacedTestCases
}

// testNamespacedOperator runs the test cases, see namespacedTestCases, against
// the namespaced operator.
func (e *e2e) testNamespacedOperator(
	manifest, namespace string,
	namespacedTestCases []testCase,
	nodes []string,
) {
	if len(namespacedTestCases) == 0 {
		return
	}

	e.logf("testing namespace operator")

	// Deploy the namespace operator. The namespace also gets deleted if the
	// test fails before, which would otherwise fail the next run of the
	// suite on the same cluster. Only an empty namespace left by such a run
	// gets reused, leftover objects of the operator fail its creation.
	e.kubectlCleanup("namespace", namespace)
	nsManifest := "\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + namespace
	e.writeAndApply(nsManifest, namespace+".yml")
	e.updateManifest(manifest, "NS_REPLACE", namespace)

	// All following operations such as create pod will be in the test namespace
	// at the same time, let's re-set the context to allow subsequent test runs
	curNs := e.getCurrentContextNamespace(config.OperatorName)
	e.kubectl("config", "set-context", "--current", "--namespace", namespace)

	defer func() {
		e.kubectl("config", "set-context", "--current", "--namespace", curNs)
	}()

	undeploy := e.deployOperatorWithCleanup(manifest)

	e.runTestCasesWithPrefix("namespaced", namespacedTestCases, nodes)

	undeploy()
	e.kubectl("delete", "namespace", namespace)
}

func doDeployCertManager(e *e2e) {
	e.logf("Deploying cert-manager")
	e.kubectl("apply", "-f", e.downloadVerified(certmanager, certmanagerSHA256))

	// https://cert-manager.io/docs/installation/kubernetes/#verifying-the-installation
	e.waitFor(
		"condition=ready",
		"--namespace", "cert-manager",
		"pod", "-l", "app.kubernetes.io/instance=cert-manager",
	)

	certManifest := `
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-test
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: test-selfsigned
  namespace: cert-manager-test
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: selfsigned-cert
  namespace: cert-manager-test
spec:
  dnsNames:
    - example.com
  secretName: selfsigned-cert-tls
  issuerRef:
    name: test-selfsigned
`

	file, err := os.CreateTemp(e.T().TempDir(), "test-resource*.yaml")
	e.Require().NoError(err)
	_, err = file.WriteString(certManifest)
	e.Require().NoError(err)
	e.Require().NoError(file.Close())

	// The cert-manager webhook takes a while to serve after its pod is ready.
	e.eventually(defaultWaitDuration, defaultWaitTime, func() error {
		_, err := e.kubectlCommand("apply", "-f", file.Name())

		return err
	})

	e.waitFor(
		"condition=Ready",
		"certificate", "selfsigned-cert",
		"--namespace", "cert-manager-test",
	)
}

// downloadVerified downloads url into the temporary directory of the test and
// returns the path of the file. It stops the test if the download keeps
// failing or the content does not have the SHA-256 checksum.
func (e *e2e) downloadVerified(url, checksum string) string {
	var content []byte

	// A stalled download is retried instead of blocking the suite.
	client := &http.Client{Timeout: 30 * time.Second}

	e.requireEventually(time.Minute, defaultPollInterval, func() error {
		req, err := http.NewRequestWithContext(e.T().Context(), http.MethodGet, url, http.NoBody)
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("downloading %s: %s", url, resp.Status)
		}

		content, err = io.ReadAll(resp.Body)

		return err
	})

	sum := sha256.Sum256(content)
	e.Require().Equal(checksum, hex.EncodeToString(sum[:]), "checksum of %s", url)

	path := filepath.Join(e.T().TempDir(), filepath.Base(url))
	e.Require().NoError(os.WriteFile(path, content, 0o600))

	return path
}

// renderedManifest returns the path of the copy of the tracked manifest,
// which the suite modifies and deploys, so that the tracked manifest stays
// untouched. The copy gets created on first use.
func (e *e2e) renderedManifest(manifest string) string {
	if path, ok := e.renderedManifests[manifest]; ok {
		return path
	}

	content, err := os.ReadFile(manifest)
	e.Require().NoError(err)
	e.Require().NoError(os.MkdirAll(renderedManifestsDir, 0o755))

	path := filepath.Join(renderedManifestsDir, filepath.Base(manifest))
	e.Require().NoError(os.WriteFile(path, content, 0o600))

	if e.renderedManifests == nil {
		e.renderedManifests = map[string]string{}
	}

	e.renderedManifests[manifest] = path

	return path
}

// resetManifest drops the changes of the copy of the manifest, the next use
// copies the tracked manifest again.
func (e *e2e) resetManifest(manifest string) {
	delete(e.renderedManifests, manifest)
}

// updateManifest replaces the regular expression src with repl in the copy of
// the manifest, see renderedManifest.
func (e *e2e) updateManifest(manifest, src, repl string) {
	path := e.renderedManifest(manifest)

	content, err := os.ReadFile(path)
	e.Require().NoError(err)

	re := regexp.MustCompile(src)
	result := re.ReplaceAllString(string(content), repl)
	err = os.WriteFile(path, []byte(result), 0o600)
	e.Require().NoError(err)
}

// deployOperatorWithCleanup deploys the operator and returns the function
// which cleans it up again. The cleanup also runs once the current test
// ends, unless it ran before, so that a test which fails with the operator
// deployed does not leave it to the next run of the suite on the same
// cluster.
func (e *e2e) deployOperatorWithCleanup(manifest string) (undeploy func()) {
	deployed := true
	undeploy = func() {
		if !deployed {
			return
		}

		deployed = false

		e.cleanupOperator(manifest)
		e.resetManifest(manifest)
	}

	e.cleanup(undeploy)
	e.deployOperator(manifest)

	return undeploy
}

func (e *e2e) deployOperator(manifest string) {
	e.createOperator(e.prepareManifest(manifest))
	e.waitForOperator()
}

// createOperator creates the objects of the operator manifest at the path and
// applies the SPOD configuration of the suite.
func (e *e2e) createOperator(path string) {
	// Deploy the operator
	e.logf("Deploying operator")
	e.kubectl("create", "-f", path)

	// Update the default SPOD configuration
	if e.spodConfig != "" {
		e.logf("Updating SPOD config")
		// Apply this server-side to avoid conflicts with the default configuration
		e.kubectl("apply", "--server-side", "--force-conflicts", "-f", e.spodConfig)
	}
}

// prepareManifest points the copy of the manifest to the images under test,
// and returns its path.
func (e *e2e) prepareManifest(manifest string) string {
	// Ensure that we do not accidentally pull the image and use the pre-loaded
	// ones from the nodes
	e.logf("Setting imagePullPolicy to '%s' in manifest: %s", e.pullPolicy, manifest)
	// Release commits use IfNotPresent instead of Always.
	e.updateManifest(manifest, "imagePullPolicy: .*", "imagePullPolicy: "+e.pullPolicy)

	const stagingImage = ".*us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/.*"

	e.updateManifest(manifest, "image: "+stagingImage, "image: "+e.testImage)
	e.updateManifest(manifest, "value: "+stagingImage, "value: "+e.testImage)

	// The copy starts from the tracked manifest again after resetManifest,
	// so the selinuxd image gets set on every deployment.
	if e.selinuxdImage != "" {
		e.updateManifest(manifest, "value: .*quay.io/.*/selinuxd.*", "value: "+e.selinuxdImage)
	}

	return e.renderedManifest(manifest)
}

// waitForOperator waits until the operator, its webhook and the spod are
// ready.
func (e *e2e) waitForOperator() {
	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	// Wait for deployment
	e.waitInOperatorNSFor(
		"condition=available",
		"deployment",
		"-l",
		"app=security-profiles-operator",
	)
	// Wait for all pods in deployment
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "app=security-profiles-operator")
	// Wait for all pods in DaemonSet
	e.waitForSpod()
	e.waitInOperatorNSFor("condition=initialized", "pod", "-l", "name=spod")
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "name=spod")
	// Wait for spod to be available. Bounded on purpose: an unbounded loop here
	// can only end at the go test timeout, which reports a whole-suite timeout
	// rather than the step that actually got stuck.
	e.eventually(defaultWaitDuration, time.Second, func() error {
		_, err := e.kubectlCommand("-n", config.OperatorName, "get", "spod", "spod")

		return err
	})
}

// getNodes returns the names of all nodes. The spod runs on the control plane
// nodes too, so the profiles get installed there as well.
func (e *e2e) getNodes() []string {
	e.logf("Getting nodes")
	nodesOutput := e.kubectl(
		"get", "nodes",
		"-o", `jsonpath={range .items[*]}{@.metadata.name}{" "}{end}`,
	)
	nodes := strings.Fields(nodesOutput)
	e.logf("Got nodes: %v", nodes)

	return nodes
}

func (e *e2e) getSeccompProfile(name string) *seccompprofileapi.SeccompProfile {
	seccompProfileJSON := e.kubectl(
		"get", "seccompprofile", name, "-o", "json",
	)
	seccompProfile := &seccompprofileapi.SeccompProfile{}
	e.Require().NoError(json.Unmarshal([]byte(seccompProfileJSON), seccompProfile))

	return seccompProfile
}

// getSeccompProfileNodeStatus returns the node status of a seccomp profile
// and fails the test unless there is exactly one.
func (e *e2e) getSeccompProfileNodeStatus(
	id, node string,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	items := e.listSeccompProfileNodeStatuses(id, node)
	if e.Len(items, 1) {
		return &items[0]
	}

	return nil
}

// listSeccompProfileNodeStatuses returns the node statuses of a seccomp
// profile on the node.
func (e *e2e) listSeccompProfileNodeStatuses(
	id, node string,
) []secprofnodestatusapi.SecurityProfileNodeStatus {
	selector := fmt.Sprintf(
		"spo.x-k8s.io/node-name=%s,spo.x-k8s.io/profile-id=SeccompProfile-%s",
		node,
		id,
	)
	seccompProfileNodeStatusJSON := e.kubectl(
		"get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	e.Require().NoError(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))

	return secpolNodeStatusList.Items
}

func (e *e2e) waitForProfileActivePodsFinalizer(name string) {
	e.logf("Waiting for active-pods finalizer on profile %s", name)

	e.eventually(30*time.Second, time.Second, func() error {
		finalizers := e.getSeccompProfile(name).GetFinalizers()
		if !slices.Contains(finalizers, "in-use-by-active-pods") {
			return fmt.Errorf("no active-pods finalizer in %v", finalizers)
		}

		return nil
	})
}

func (e *e2e) getAllSeccompProfileNodeStatuses(
	id string,
) *secprofnodestatusapi.SecurityProfileNodeStatusList {
	selector := "spo.x-k8s.io/profile-id=SeccompProfile-" + id
	seccompProfileNodeStatusJSON := e.kubectl(
		"get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	e.Require().NoError(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))

	return secpolNodeStatusList
}

func (e *e2e) getCurrentContextNamespace(alt string) string {
	ctxns := e.kubectl("config", "view", "--minify", "-o", "jsonpath={..namespace}")
	if ctxns == "" {
		ctxns = alt
	}

	return ctxns
}

// writeAndCreate creates the objects of the manifest. Deleting them again is
// up to the caller.
func (e *e2e) writeAndCreate(manifest, filePattern string) {
	e.writeAndDo("create", manifest, filePattern)
}

// writeAndApply applies the objects of the manifest. Deleting them again is up
// to the caller.
func (e *e2e) writeAndApply(manifest, filePattern string) {
	e.writeAndDo("apply", manifest, filePattern)
}

func (e *e2e) writeAndDo(verb, manifest, filePattern string) {
	file, err := os.CreateTemp(e.T().TempDir(), filePattern)
	e.Require().NoError(err)

	_, err = file.WriteString(manifest)
	e.Require().NoError(err)
	err = file.Close()
	e.Require().NoError(err)
	e.kubectl(verb, "-f", file.Name())
}

// waitForPodCreated waits until the containers of the pod got created.
func (e *e2e) waitForPodCreated(name string) {
	e.eventually(defaultWaitDuration, time.Second, func() error {
		if output := e.kubectl("get", "pod", name); strings.Contains(output, "ContainerCreating") {
			return fmt.Errorf("the containers of pod %s are still being created", name)
		}

		return nil
	})
}

// poll calls cond every interval until it returns nil, or returns the last
// error of cond once the timeout passes.
func poll(timeout, interval time.Duration, cond func() error) error {
	deadline := time.Now().Add(timeout)

	for {
		err := cond()
		if err == nil {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("gave up after %s: %w", timeout, err)
		}

		time.Sleep(interval)
	}
}

// eventually polls cond every interval until it returns nil. Once the timeout
// passes, it fails the test with the last error of cond, so that the failure
// says what never happened.
func (e *e2e) eventually(timeout, interval time.Duration, cond func() error) {
	if err := poll(timeout, interval, cond); err != nil {
		e.Failf("condition not met", "%v", err)
	}
}

// consistently fails the test if cond fails before the timeout passes.
func (e *e2e) consistently(timeout, interval time.Duration, cond func() error) {
	deadline := time.Now().Add(timeout)

	for {
		if err := cond(); err != nil {
			e.Failf("condition not kept", "%v", err)

			return
		}

		if time.Now().After(deadline) {
			return
		}

		time.Sleep(interval)
	}
}

// requireEventually is eventually, but stops the test when cond is never met.
func (e *e2e) requireEventually(timeout, interval time.Duration, cond func() error) {
	if err := poll(timeout, interval, cond); err != nil {
		e.FailNowf("condition not met", "%v", err)
	}
}

// kubectlCleanup deletes the objects once the current test ends, also if it
// failed. A failed delete is only logged, so that it does not skip the other
// cleanups like a failed deferred kubectl call does. The namespace is the one
// of the current context now, since the test may switch the context before it
// ends.
func (e *e2e) kubectlCleanup(args ...string) {
	namespace := e.getCurrentContextNamespace(defaultNamespace)
	cmd := withDeleteTimeout(append(
		[]string{"delete", "--ignore-not-found", "--namespace", namespace}, args...,
	))

	e.cleanup(func() {
		if _, err := e.kubectlCommand(cmd...); err != nil {
			e.logf("Cleanup failed: kubectl %s: %v", strings.Join(cmd, " "), err)
		}
	})
}

// cleanup runs fn once the current test ends, also if it failed, unless
// TearDownTest deleted the cluster already. The suite points at the parent
// test by then, so fn runs with the current test again, otherwise a failed
// assertion of fn would stop the parent test.
func (e *e2e) cleanup(fn func()) {
	t := e.T()

	t.Cleanup(func() {
		if e.clusterTornDown {
			return
		}

		parent := e.T()

		e.SetT(t)
		defer e.SetT(parent)

		fn()
	})
}

// unmatchedLogs returns an error which lists the conditions no line of the
// logs matches, or nil if all match.
func unmatchedLogs(logs string, conditions []*regexp.Regexp) error {
	var missing []string

	for _, condition := range conditions {
		if !condition.MatchString(logs) {
			missing = append(missing, condition.String())
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("no log line matches %q", missing)
	}

	return nil
}

// nodeFileExists reports whether the file exists on the node, without failing
// the test if it does not. Its directory has to exist.
func (e *e2e) nodeFileExists(node, filePath string) bool {
	return e.execNode(
		node, "find", filepath.Dir(filePath), "-maxdepth", "1", "-name", filepath.Base(filePath),
	) != ""
}

func (e *e2e) getSELinuxPolicyName(kind, policy string) string {
	usageStr := e.getSELinuxPolicyUsage(kind, policy)
	// Udica (the library that helps out generate SELinux policies),
	// adds .process in the end of the usage. So we need to remove it
	// to get the module name
	return strings.TrimSuffix(usageStr, ".process")
}

func (e *e2e) getSELinuxPolicyUsage(kind, policy string) string {
	ns := e.getCurrentContextNamespace(defaultNamespace)
	// This describes the usage string, which is not necessarily
	// the name of the policy in the node
	return e.kubectl("get", kind, "-n", ns, policy, "-o", "jsonpath={.status.usage}")
}

func (e *e2e) waitForSpod() {
	e.eventually(150*time.Second, defaultPollInterval, func() error {
		output, err := runCommandStatus(
			false, e.kubectlPath, "-n", config.OperatorName,
			"get", "pod", "-l", "name=spod",
		)
		if err != nil {
			return fmt.Errorf("listing the spod pods: %w", err)
		}

		// Any other failure of kubectl, like a refused connection, is not
		// a spod pod either.
		if !output.Success() {
			return fmt.Errorf("listing the spod pods: %s", output.Error())
		}

		if strings.Contains(output.Error(), "No resources found") {
			return errors.New("no spod pods")
		}

		return nil
	})
}

func (e *e2e) retryGet(args ...string) string {
	var result string

	e.eventually(time.Minute, defaultPollInterval, func() error {
		output, err := runCommandStatus(
			false, e.kubectlPath, append([]string{"get"}, args...)...,
		)
		if err != nil {
			return fmt.Errorf("kubectl get %s: %w", strings.Join(args, " "), err)
		}

		if !output.Success() {
			return fmt.Errorf("kubectl get %s: %s", strings.Join(args, " "), output.Error())
		}

		result = output.OutputTrimNL()

		return nil
	})

	return result
}

func (e *e2e) exists(args ...string) bool {
	output, err := runCommandStatus(
		false, e.kubectlPath, append([]string{"get"}, args...)...,
	)
	e.Require().NoError(err)

	if output.Success() {
		return true
	}

	// Only a missing object is an answer, any other failure of kubectl is not.
	e.Require().Contains(output.Error(), "not found")

	return false
}

func (e *e2e) getSeccompPolicyID(profile string) string {
	ns := e.getCurrentContextNamespace(defaultNamespace)

	return e.kubectl(
		"get",
		"sp",
		"-n",
		ns,
		profile,
		"-o",
		"jsonpath={.metadata.labels.spo\\.x-k8s\\.io/profile-id}",
	)
}
