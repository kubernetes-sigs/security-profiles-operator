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
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/suite"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/release-utils/command"
	"sigs.k8s.io/release-utils/helpers"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	kindVersion = "v0.33.0"
	kindImage   = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
)

// kindSHA512 are the checksums of the kind binaries, keyed by
// runtime.GOOS + "-" + runtime.GOARCH.
//
//nolint:lll // full length SHA
var kindSHA512 = map[string]string{
	"darwin-amd64": "5dccea9fd7fef0d5f5e8212bc4683389b13c4724b55057911da9d34bb6b605641e024affaa34b17b672ed22df4534cdcbc56a505a3078d6f17a10ac81fbd5f10",
	"darwin-arm64": "443edbc6dac7bf44025e90dafe0c66fd6489ee37ed58c80647578b8fcdd39567f986389b4bf38a0de0529ba7415da9c5c2ef9860b0227f3708d30c586671869b",
	"linux-amd64":  "f58a029ef8dee72f7fcf0345a5731795de0745ee6c955efd24801ced8409395cd2a4dc0ca41663c43231a48e94a5375cd01e63bc37b4557bf708e9ce6703fffa",
	"linux-arm64":  "034585fbb3766f34c3cdbc127b145c76904073918e2af76e31a81349aa2c67979e35ab780cc4a1cb1dadc5df04ae3b9c2984c1b382f1cff6b4ee48b560b7f048",
}

// The environment variables of the suite. The table in doc/hacking.md
// documents them, keep both in sync.
var (
	// E2E_CLUSTER_TYPE selects the cluster driver: kind (the default),
	// vanilla or openshift.
	clusterType = os.Getenv("E2E_CLUSTER_TYPE")
	// E2E_SKIP_BUILD_IMAGES skips building the operator image before pushing
	// it, OpenShift only.
	envSkipBuildImages = os.Getenv("E2E_SKIP_BUILD_IMAGES")
	// E2E_SPO_IMAGE is the operator image to test.
	envTestImage = os.Getenv("E2E_SPO_IMAGE")
	// E2E_SELINUXD_IMAGE is the selinuxd image to deploy.
	envSelinuxdTestImage = os.Getenv("E2E_SELINUXD_IMAGE")
	// E2E_SPOD_CONFIG is a SPOD manifest which is applied after the
	// deployment, to change the default configuration.
	spodConfig = os.Getenv("E2E_SPOD_CONFIG")
	// E2E_SKIP_FLAKY_TESTS skips the quarantined test cases, see the flaky
	// field of testCase. Defaults to false.
	envSkipFlakyTests = os.Getenv("E2E_SKIP_FLAKY_TESTS")
	// E2E_SKIP_NAMESPACED_TESTS skips the second run of the test cases
	// against the namespaced operator.
	envSkipNamespacedTests = os.Getenv("E2E_SKIP_NAMESPACED_TESTS")
	// E2E_TEST_SELINUX enables the SELinux test cases.
	envSelinuxTestsEnabled = os.Getenv("E2E_TEST_SELINUX")
	// E2E_TEST_LOG_ENRICHER enables the log enricher test cases.
	envLogEnricherTestsEnabled = os.Getenv("E2E_TEST_LOG_ENRICHER")
	// E2E_TEST_JSON_ENRICHER enables the JSON enricher test cases.
	envJsonEnricherTestsEnabled = os.Getenv("E2E_TEST_JSON_ENRICHER")
	// E2E_TEST_SECCOMP enables the seccomp test cases, defaults to true.
	envSeccompTestsEnabled = os.Getenv("E2E_TEST_SECCOMP")
	// E2E_TEST_BPF_RECORDER enables the bpf recorder test cases.
	envBpfRecorderTestsEnabled = os.Getenv("E2E_TEST_BPF_RECORDER")
	// E2E_TEST_BPF_LOG_ENRICHER enables the log enricher test case with the
	// BPF source.
	envBpfEnricherTestsEnabled = os.Getenv("E2E_TEST_BPF_LOG_ENRICHER")
	// E2E_TEST_WEBHOOK_CONFIG enables the webhook configuration test cases,
	// defaults to true.
	envWebhookConfigTestsEnabled = os.Getenv("E2E_TEST_WEBHOOK_CONFIG")
	// E2E_TEST_WEBHOOK_HTTP enables the webhook HTTP version test case,
	// defaults to true.
	envWebhookHTTPTestsEnabled = os.Getenv("E2E_TEST_WEBHOOK_HTTP")
	// E2E_TEST_METRICS_HTTP enables the metrics HTTP version test case,
	// defaults to true.
	envMetricsHTTPTestsEnabled = os.Getenv("E2E_TEST_METRICS_HTTP")
	// E2E_ARTIFACTS_DIR is the directory the diagnostics of failed tests are
	// written to, one directory per test. They are logged when unset.
	envArtifactsDir = os.Getenv("E2E_ARTIFACTS_DIR")
	// CONTAINER_RUNTIME is the container runtime on the test host, docker
	// or podman.
	containerRuntime = os.Getenv("CONTAINER_RUNTIME")
	// NODE_ROOTFS_PREFIX is the prefix of the node root filesystem, when
	// the node is reached through a chroot.
	nodeRootfsPrefix = os.Getenv("NODE_ROOTFS_PREFIX")
	// OPERATOR_MANIFEST is the cluster wide operator manifest to deploy,
	// defaults to deploy/operator.yaml.
	operatorManifest = os.Getenv("OPERATOR_MANIFEST")
)

const (
	clusterTypeKind      = "kind"
	clusterTypeVanilla   = "vanilla"
	clusterTypeOpenShift = "openshift"
)

const (
	containerRuntimeDocker = "docker"
)

const (
	defaultManifest = "deploy/operator.yaml"
)

const (
	nsBindingEnabled    = "spo-binding-enabled"
	nsBindingDisabled   = "spo-binding-disabled"
	nsRecordingEnabled  = "spo-recording-enabled"
	nsRecordingDisabled = "spo-recording-disabled"
)

type e2e struct {
	suite.Suite
	containerRuntime    string
	kubectlPath         string
	testImage           string
	selinuxdImage       string
	pullPolicy          string
	spodConfig          string
	nodeRootfsPrefix    string
	operatorManifest    string
	selinuxEnabled      bool
	logEnricherEnabled  bool
	jsonEnricherEnabled bool
	testSeccomp         bool
	bpfRecorderEnabled  bool
	bpfEnricherEnabled  bool
	skipNamespacedTests bool
	skipFlakyTests      bool
	testWebhookConfig   bool
	testWebhookHTTP     bool
	testMetricsHTTP     bool
	artifactsDir        string
	logger              logr.Logger
	execNode            func(node string, args ...string) string
	// nodeCommand runs a command on the node like execNode, but returns
	// the error instead of failing the test, for the diagnostics.
	nodeCommand       func(node string, args ...string) (string, error)
	waitForReadyPods  func()
	deployCertManager func()
	setupRecordingSa  func(namespace string)
	// renderedManifests maps the tracked manifests to their rendered
	// copies, see renderManifest.
	renderedManifests map[string]string
	// testStart and subTestStart are when the current test and sub test
	// started, to dump the logs since then.
	testStart        time.Time
	subTestStart     time.Time
	diagnosticsTimer *time.Timer
}

func defaultWaitForReadyPods(e *e2e) {
	e.logf("Waiting for all cluster pods to become ready")
	// Only the pods of the cluster itself, because a failed test can leave
	// its pods behind, which would fail every following run as well.
	// Terminated pods never become ready, like the node debugging pods which
	// tests leave behind because kubectl debug cannot remove them.
	e.waitFor(
		"condition=ready", "pods", "--all", "--namespace", "kube-system",
		"--field-selector", "status.phase!=Succeeded,status.phase!=Failed",
	)
}

type kinde2e struct {
	e2e
	kindPath    string
	clusterName string
}

type openShifte2e struct {
	e2e
	skipBuildImages bool
	skipPushImages  bool
}

type vanilla struct {
	e2e
}

// We're unable to use parallel tests because of our usage of testify/suite.
// See https://github.com/stretchr/testify/issues/187
//
//nolint:paralleltest // should not run in parallel
func TestSuite(t *testing.T) {
	fmt.Printf("cluster-type: %s\n", clusterType)
	fmt.Printf("container-runtime: %s\n", containerRuntime)

	testImage := envTestImage

	selinuxEnabled, err := strconv.ParseBool(envSelinuxTestsEnabled)
	if err != nil {
		selinuxEnabled = false
	}

	logEnricherEnabled, err := strconv.ParseBool(envLogEnricherTestsEnabled)
	if err != nil {
		logEnricherEnabled = false
	}

	jsonEnricherEnabled, err := strconv.ParseBool(envJsonEnricherTestsEnabled)
	if err != nil {
		jsonEnricherEnabled = false
	}

	testSeccomp, err := strconv.ParseBool(envSeccompTestsEnabled)
	if err != nil {
		testSeccomp = true
	}

	bpfRecorderEnabled, err := strconv.ParseBool(envBpfRecorderTestsEnabled)
	if err != nil {
		bpfRecorderEnabled = false
	}

	bpfEnricherEnabled, err := strconv.ParseBool(envBpfEnricherTestsEnabled)
	if err != nil {
		bpfEnricherEnabled = false
	}

	skipNamespacedTests, err := strconv.ParseBool(envSkipNamespacedTests)
	if err != nil {
		skipNamespacedTests = false
	}

	skipFlakyTests, err := strconv.ParseBool(envSkipFlakyTests)
	if err != nil {
		skipFlakyTests = false
	}

	testWebhookConfig, err := strconv.ParseBool(envWebhookConfigTestsEnabled)
	if err != nil {
		testWebhookConfig = true
	}

	testWebhookHTTP, err := strconv.ParseBool(envWebhookHTTPTestsEnabled)
	if err != nil {
		testWebhookHTTP = true
	}

	testMetricsHTTP, err := strconv.ParseBool(envMetricsHTTPTestsEnabled)
	if err != nil {
		testMetricsHTTP = true
	}

	if operatorManifest == "" {
		operatorManifest = defaultManifest
	}

	selinuxdImage := envSelinuxdTestImage
	if selinuxdImage == "" {
		selinuxdImage = "quay.io/security-profiles-operator/selinuxd"
	}

	switch {
	case clusterType == "" || strings.EqualFold(clusterType, clusterTypeKind):
		if testImage == "" {
			testImage = config.OperatorName + ":latest"
		}

		suite.Run(t, &kinde2e{
			e2e{
				logger:              textlogger.NewLogger(textlogger.NewConfig()),
				pullPolicy:          "Never",
				testImage:           testImage,
				spodConfig:          spodConfig,
				containerRuntime:    containerRuntime,
				nodeRootfsPrefix:    nodeRootfsPrefix,
				selinuxEnabled:      selinuxEnabled,
				logEnricherEnabled:  logEnricherEnabled,
				jsonEnricherEnabled: jsonEnricherEnabled,
				testSeccomp:         testSeccomp,
				selinuxdImage:       selinuxdImage,
				bpfRecorderEnabled:  bpfRecorderEnabled,
				bpfEnricherEnabled:  bpfEnricherEnabled,
				skipNamespacedTests: skipNamespacedTests,
				operatorManifest:    operatorManifest,
				testWebhookConfig:   testWebhookConfig,
				testWebhookHTTP:     testWebhookHTTP,
				testMetricsHTTP:     testMetricsHTTP,
				skipFlakyTests:      skipFlakyTests,
				artifactsDir:        envArtifactsDir,
			},
			"", "",
		})
	case strings.EqualFold(clusterType, clusterTypeOpenShift):
		skipBuildImages, err := strconv.ParseBool(envSkipBuildImages)
		if err != nil {
			skipBuildImages = false
		}
		// we can skip pushing the image to the registry if
		// an image was given through the environment variable
		skipPushImages := testImage != ""

		suite.Run(t, &openShifte2e{
			e2e{
				logger: textlogger.NewLogger(textlogger.NewConfig()),
				// Need to pull the image as it'll be uploaded to the cluster OCP
				// image registry and not on the nodes.
				pullPolicy:          "Always",
				testImage:           testImage,
				spodConfig:          spodConfig,
				containerRuntime:    containerRuntime,
				nodeRootfsPrefix:    nodeRootfsPrefix,
				selinuxEnabled:      selinuxEnabled,
				logEnricherEnabled:  logEnricherEnabled,
				jsonEnricherEnabled: jsonEnricherEnabled,
				testSeccomp:         testSeccomp,
				selinuxdImage:       selinuxdImage,
				bpfRecorderEnabled:  bpfRecorderEnabled,
				bpfEnricherEnabled:  bpfEnricherEnabled,
				skipNamespacedTests: skipNamespacedTests,
				operatorManifest:    operatorManifest,
				testWebhookConfig:   testWebhookConfig,
				testWebhookHTTP:     testWebhookHTTP,
				testMetricsHTTP:     testMetricsHTTP,
				skipFlakyTests:      skipFlakyTests,
				artifactsDir:        envArtifactsDir,
			},
			skipBuildImages,
			skipPushImages,
		})
	case strings.EqualFold(clusterType, clusterTypeVanilla):
		if testImage == "" {
			testImage = "localhost/" + config.OperatorName + ":latest"
		}

		suite.Run(t, &vanilla{
			e2e{
				logger:              textlogger.NewLogger(textlogger.NewConfig()),
				pullPolicy:          "Never",
				testImage:           testImage,
				spodConfig:          spodConfig,
				containerRuntime:    containerRuntime,
				nodeRootfsPrefix:    nodeRootfsPrefix,
				selinuxEnabled:      selinuxEnabled,
				logEnricherEnabled:  logEnricherEnabled,
				jsonEnricherEnabled: jsonEnricherEnabled,
				testSeccomp:         testSeccomp,
				selinuxdImage:       selinuxdImage,
				bpfRecorderEnabled:  bpfRecorderEnabled,
				bpfEnricherEnabled:  bpfEnricherEnabled,
				skipNamespacedTests: skipNamespacedTests,
				operatorManifest:    operatorManifest,
				testWebhookConfig:   testWebhookConfig,
				testWebhookHTTP:     testWebhookHTTP,
				testMetricsHTTP:     testMetricsHTTP,
				skipFlakyTests:      skipFlakyTests,
				artifactsDir:        envArtifactsDir,
			},
		})
	default:
		t.Fatalf("Unknown cluster type.")
	}
}

// SetupSuite downloads kind and searches for kubectl in $PATH.
func (e *kinde2e) SetupSuite() {
	e.logf("Setting up suite")
	command.SetGlobalVerbose(true)
	// Override execNode and waitForReadyPods functions
	e.execNode = e.execNodeKind
	e.nodeCommand = e.nodeCommandKind
	e.waitForReadyPods = e.waitForReadyPodsKind
	e.deployCertManager = e.deployCertManagerKind
	e.setupRecordingSa = e.deployRecordingSa
	parentCwd := e.setWorkDir()
	buildDir := filepath.Join(parentCwd, "build")
	e.Require().NoError(os.MkdirAll(buildDir, 0o755))

	e.kindPath = filepath.Join(buildDir, "kind")
	platform := runtime.GOOS + "-" + e.hostArch()

	sha512, ok := kindSHA512[platform]
	e.Require().True(ok, "no kind binary for %s", platform)

	e.downloadAndVerify(
		fmt.Sprintf("https://github.com/kubernetes-sigs/kind/releases/download/%s/kind-%s",
			kindVersion, platform),
		e.kindPath,
		sha512,
	)

	var err error

	e.kubectlPath, err = exec.LookPath("kubectl")
	e.updateManifest(
		e.operatorManifest,
		"value: .*quay.io/.*/selinuxd.*",
		"value: "+e.selinuxdImage,
	)
	e.Require().NoError(err)
}

// SetupTest starts a fresh kind cluster for each test.
func (e *kinde2e) SetupTest() {
	// Deploy the cluster
	e.logf("Deploying the cluster")
	e.clusterName = fmt.Sprintf("spo-e2e-%d", time.Now().Unix())

	cmd := exec.Command(
		e.kindPath, "create", "cluster",
		"--name="+e.clusterName,
		"--image="+kindImage,
		"-v=3",
		"--config=test/kind-config.yaml",
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	e.Require().NoError(cmd.Run())

	// Wait for the nodes to  be ready
	e.logf("Waiting for cluster to be ready")
	e.waitFor("condition=ready", "nodes", "--all")

	// Build and load the test image
	e.logf("Building operator container image")
	e.run("make", "image", "IMAGE="+e.testImage)
	e.logf("Loading container images into nodes")
	e.run(
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, e.testImage,
	)
	e.run(
		containerRuntime, "pull", e.selinuxdImage,
	)
	e.run(
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, e.selinuxdImage,
	)
}

// TearDownTest stops the kind cluster.
func (e *kinde2e) TearDownTest() {
	e.logf("#### Snapshot of cert-manager namespace ####")
	e.kubectl("--namespace", "cert-manager", "describe", "all")
	e.logf("########")
	e.logf("#### Snapshot of security-profiles-operator namespace ####")
	e.kubectl("--namespace", "security-profiles-operator", "describe", "all")
	e.logf("########")

	e.logf("Destroying cluster")
	e.run(
		e.kindPath, "delete", "cluster",
		"--name="+e.clusterName,
		"-v=3",
	)
}

// hostArch returns the architecture of the host in the notation of Go, from
// uname -m, like the kind release binaries are named.
func (e *e2e) hostArch() string {
	machine, err := e.runCommand("uname", "-m")
	e.Require().NoError(err)

	switch machine {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

func (e *kinde2e) execNodeKind(node string, args ...string) string {
	return e.run(containerRuntime, append([]string{"exec", node}, args...)...)
}

func (e *kinde2e) nodeCommandKind(node string, args ...string) (string, error) {
	return e.runCommand(containerRuntime, append([]string{"exec", node}, args...)...)
}

func (e *e2e) waitForReadyPodsKind() {
	defaultWaitForReadyPods(e)
}

func (e *e2e) deployCertManagerKind() {
	doDeployCertManager(e)
}

func (e *openShifte2e) SetupSuite() {
	var err error

	e.logf("Setting up suite")
	command.SetGlobalVerbose(true)
	// Override execNode and waitForReadyPods functions
	e.execNode = e.execNodeOCP
	e.nodeCommand = e.nodeCommandOCP
	e.waitForReadyPods = e.waitForReadyPodsOCP
	e.deployCertManager = e.deployCertManagerOCP
	e.setupRecordingSa = e.deployRecordingSaOcp
	e.setWorkDir()

	e.kubectlPath, err = exec.LookPath("oc")
	e.Require().NoError(err)

	e.logf("Using deployed OpenShift cluster")

	e.logf("Waiting for cluster to be ready")
	e.waitFor("condition=ready", "nodes", "--all")

	if !e.skipPushImages {
		e.logf("pushing SPO image to openshift registry")
		e.pushImageToRegistry()
	}
}

func (e *openShifte2e) TearDownSuite() {
	if !e.skipPushImages {
		e.kubectl(
			"delete", "imagestream", "-n", "openshift", config.OperatorName,
		)
	}
}

func (e *openShifte2e) SetupTest() {
	e.logf("Setting up test")
}

// TearDownTest stops the kind cluster.
func (e *openShifte2e) TearDownTest() {
	e.logf("Tearing down test")
}

func (e *openShifte2e) pushImageToRegistry() {
	e.logf("Exposing registry")

	e.kubectl("patch", "configs.imageregistry.operator.openshift.io/cluster",
		"--patch", "{\"spec\":{\"defaultRoute\":true}}", "--type=merge")
	defer e.kubectl("patch", "configs.imageregistry.operator.openshift.io/cluster",
		"--patch", "{\"spec\":{\"defaultRoute\":false}}", "--type=merge")

	testImageRef := config.OperatorName + ":latest"

	// Build and load the test image
	if !e.skipBuildImages {
		e.logf("Building operator container image")
		e.run("make", "image", "IMAGE="+testImageRef)
	}

	e.logf("Loading container image into nodes")

	// Get credentials
	user := e.kubectl("whoami")
	token := e.kubectl("whoami", "-t")
	registry := e.kubectl(
		"get", "route", "default-route", "-n", "openshift-image-registry",
		"--template={{ .spec.host }}",
	)

	e.run(
		containerRuntime, "login", "--tls-verify=false", "-u", user, "-p", token, registry,
	)

	registryTarget := fmt.Sprintf("%s/openshift/%s", registry, testImageRef)
	e.run(
		containerRuntime, "push", "--tls-verify=false", testImageRef, registryTarget,
	)
	// Enable "local" lookup without full path
	e.kubectl("patch", "imagestream", "-n", "openshift", config.OperatorName,
		"--patch", "{\"spec\":{\"lookupPolicy\":{\"local\":true}}}", "--type=merge")

	e.testImage = e.kubectl(
		"get",
		"imagestreamtag",
		"-n",
		"openshift",
		testImageRef,
		"-o",
		"jsonpath={.image.dockerImageReference}",
	)
}

func (e *openShifte2e) execNodeOCP(node string, args ...string) string {
	return e.kubectl(
		"debug", "-q", "node/"+node, "--",
		"chroot", "/host", "/bin/bash", "-c",
		strings.Join(args, " "),
	)
}

func (e *openShifte2e) nodeCommandOCP(node string, args ...string) (string, error) {
	return e.kubectlCommand(
		"debug", "-q", "node/"+node, "--",
		"chroot", "/host", "/bin/bash", "-c",
		strings.Join(args, " "),
	)
}

func (e *e2e) waitForReadyPodsOCP() {
	// intentionally not waiting for pods, it is presumed a test driver or the developer
	// ensure the cluster is up before the test runs. At least for now.
	// this is a kludge to help run the tests on OCP CI where there's a ephemeral namespace that goes away
	// as the test is starting. Without explicitly setting the namespace, the OCP CI tests fail with:
	// error when creating "test/recording_sa.yaml": namespaces "ci-op-hq1cv14k" not found
	e.kubectl("config", "set-context", "--current", "--namespace", config.OperatorName)
}

func (e *e2e) deployCertManagerOCP() {
	// intentionally blank, OCP creates certs on its own
}

func (e *e2e) deployRecordingSaOcp(namespace string) {
	e.deployRecordingSa(namespace)
	e.deployRecordingRole(namespace)
	e.deployRecordingRoleBinding(namespace)
}

func (e *vanilla) SetupSuite() {
	var err error

	e.logf("Setting up suite")
	e.setWorkDir()

	// Override execNode and waitForReadyPods functions
	e.execNode = e.execNodeVanilla
	e.nodeCommand = e.nodeCommandVanilla
	e.kubectlPath, err = exec.LookPath("kubectl")
	e.waitForReadyPods = e.waitForReadyPodsVanilla
	e.deployCertManager = e.deployCertManagerVanilla
	e.setupRecordingSa = e.deployRecordingSa
	e.updateManifest(
		e.operatorManifest,
		"value: .*quay.io/.*/selinuxd.*",
		"value: "+e.selinuxdImage,
	)
	e.Require().NoError(err)
}

func (e *vanilla) SetupTest() {
	e.logf("Setting up test")

	// A locally built image cannot be pulled.
	if e.selinuxEnabled {
		_, err := e.runCommand(containerRuntime, "image", "inspect", e.selinuxdImage)
		if err != nil {
			e.run(containerRuntime, "pull", e.selinuxdImage)
		}
	}
}

func (e *vanilla) TearDownTest() {
}

func (e *vanilla) execNodeVanilla(_ string, args ...string) string {
	return e.run(args[0], args[1:]...)
}

func (e *vanilla) nodeCommandVanilla(_ string, args ...string) (string, error) {
	return e.runCommand(args[0], args[1:]...)
}

func (e *e2e) waitForReadyPodsVanilla() {
	defaultWaitForReadyPods(e)
}

func (e *e2e) deployCertManagerVanilla() {
	doDeployCertManager(e)
}

func (e *e2e) setWorkDir() string {
	cwd, err := os.Getwd()
	e.Require().NoError(err)

	parentCwd := filepath.Dir(cwd)
	e.NoError(os.Chdir(parentCwd))

	return parentCwd
}

func (e *e2e) run(cmd string, args ...string) string {
	output, err := e.runCommand(cmd, args...)
	e.Require().NoError(err)

	return output
}

func (e *e2e) runCommand(cmd string, args ...string) (string, error) {
	output, err := command.New(cmd, args...).RunSuccessOutput()
	if err != nil {
		return "", err
	}

	if output != nil {
		return output.OutputTrimNL(), nil
	}

	return "", nil
}

func (e *e2e) downloadAndVerify(url, binaryPath, sha512 string) {
	if !helpers.Exists(binaryPath) {
		e.logf("Downloading %s", binaryPath)
		e.run("curl", "-o", binaryPath, "-fL", url)
		e.Require().NoError(os.Chmod(binaryPath, 0o700))
		e.verifySHA512(binaryPath, sha512)
	}
}

func (e *e2e) verifySHA512(binaryPath, sha512 string) {
	e.NoError(command.New("sha512sum", binaryPath).
		Pipe("grep", sha512).
		RunSilentSuccess(),
	)
}

func (e *e2e) kubectl(args ...string) string {
	return e.run(e.kubectlPath, withDeleteTimeout(args)...)
}

// withDeleteTimeout bounds how long a kubectl delete waits for the object to
// be gone. It waits forever by default, so a finalizer which never gets
// removed hangs the test instead of failing it, and skips the diagnostics.
func withDeleteTimeout(args []string) []string {
	if !slices.Contains(args, "delete") || slices.ContainsFunc(args, func(arg string) bool {
		return strings.HasPrefix(arg, "--timeout")
	}) {
		return args
	}

	return append(slices.Clone(args), "--timeout", defaultLongOpTimeout)
}

func (e *e2e) kubectlCommand(args ...string) (string, error) {
	return e.runCommand(e.kubectlPath, args...)
}

func (e *e2e) kubectlOperatorNS(args ...string) string {
	return e.kubectl(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
}

func (e *e2e) kubectlRun(args ...string) string {
	return e.kubectl(kubectlRunArgs(args...)...)
}

// kubectlRunArgs returns the kubectl arguments to run a command in a new pod.
func kubectlRunArgs(args ...string) []string {
	return append([]string{
		"run",
		"--pod-running-timeout=5m",
		"--rm",
		"-i",
		"--restart=Never",
		"--image=registry.fedoraproject.org/fedora-minimal:latest",
	}, args...)
}

func (e *e2e) kubectlRunOperatorNS(args ...string) string {
	return e.kubectlRun(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
}

const (
	curlBaseCMD    = "curl -ksL --connect-timeout 10 --retry 5 --retry-delay 3 --show-error "
	headerAuth     = "-H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" "
	curlCMD        = curlBaseCMD + headerAuth + "-f "
	curlHTTPVerCMD = curlBaseCMD + headerAuth + "-I -w '%{http_version}\n' -o/dev/null "
	metricsURL     = "https://metrics.security-profiles-operator.svc.cluster.local/"
	webhooksURL    = "https://webhook-service.security-profiles-operator.svc.cluster.local/"
	curlSpodCMD    = curlCMD + metricsURL + "metrics-spod"
	curlCtrlCMD    = curlCMD + metricsURL + "metrics"
)

func (e *e2e) runAndRetryPodCMD(podCMD string) string {
	// Sometimes the metrics command does not output anything in CI, or its
	// TLS connection fails. We fix that by retrying the metrics retrieval
	// until podCommandTimeout passes, since curl does not retry TLS errors
	// itself.
	var output string

	e.eventually(podCommandTimeout, defaultPollInterval, func() error {
		letters := []rune("abcdefghijklmnopqrstuvwxyz")
		b := make([]rune, 10)

		for i := range b {
			b[i] = letters[rand.IntN(len(letters))] //nolint:gosec // not security-sensitive
		}

		var err error

		output, err = e.kubectlCommand(kubectlRunArgs(
			"-n", config.OperatorName, "pod-"+string(b), "--", "bash", "-c", podCMD,
		)...)
		if err != nil {
			output = ""

			e.logf("Retrying the pod command: %v", err)

			return fmt.Errorf("running pod command: %w", err)
		}

		if len(strings.Split(output, "\n")) > 1 {
			return nil
		}

		output = ""

		e.logf("Retrying the pod command: no output")

		return errors.New("no output from pod command")
	})

	return output
}

func (e *e2e) waitFor(args ...string) {
	e.kubectl(
		append([]string{"wait", "--timeout", defaultWaitTimeout, "--for"}, args...)...,
	)
}

func (e *e2e) waitForProfile(args ...string) {
	e.waitFor(
		append([]string{"jsonpath={.status.status}=Installed", "sp"}, args...)...,
	)
}

func (e *e2e) waitInOperatorNSFor(args ...string) {
	e.kubectlOperatorNS(
		append([]string{"wait", "--timeout", defaultWaitTimeout, "--for"}, args...)...,
	)
}

// patchSpod merge patches the SPOD and waits until the change is rolled out.
func (e *e2e) patchSpod(patch string) {
	generation := e.spodDaemonSetGeneration()

	output := e.kubectlOperatorNS("patch", "spod", "spod", "-p", patch, "--type=merge")
	// Waiting for a rollout would only run into the timeout for the daemon set
	// generation.
	if strings.Contains(output, "(no change)") {
		return
	}

	e.waitForSpodRollout(generation)
}

// spodDaemonSetGeneration returns the generation of the spod daemon set, to
// pass to waitForSpodRollout after changing the SPOD.
func (e *e2e) spodDaemonSetGeneration() string {
	return e.kubectlOperatorNS("get", "ds", "spod", "-o", "jsonpath={.metadata.generation}")
}

// waitForSpodRollout waits until the operator applied a change of the SPOD to
// the spod daemon set and the daemon set is rolled out. The ready condition of
// the SPOD can still be the one from before the change, so the new daemon set
// generation tells when the operator got to it. Changes which the daemon set
// does not reflect leave the generation alone, so the wait for it only logs
// that it gave up after spodGenerationTimeout, and the waits for the SPOD and
// the rollout below still fail the test if those never finish.
func (e *e2e) waitForSpodRollout(previousGeneration string) {
	if err := poll(spodGenerationTimeout, time.Second, func() error {
		if generation := e.spodDaemonSetGeneration(); generation == previousGeneration {
			return fmt.Errorf("spod daemon set still at generation %s", generation)
		}

		return nil
	}); err != nil {
		e.logf("Assuming the SPOD change does not affect the daemon set: %v", err)
	}

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLongOpTimeout)
}

func (e *e2e) logf(format string, a ...any) {
	e.logger.Info(fmt.Sprintf(format, a...))
}

func (e *e2e) selinuxOnlyTestCase() {
	if !e.selinuxEnabled {
		e.T().Skip("Skipping SELinux-related test")
	}

	e.enableSelinuxInSpod()
}

func (e *e2e) enableSelinuxInSpod() {
	selinuxEnabledInSPODDS := e.kubectlOperatorNS("get", "ds", "spod", "-o", "yaml")
	if !strings.Contains(selinuxEnabledInSPODDS, "--with-selinux=true") {
		e.logf("Enable selinux in SPOD")
		e.patchSpod(
			`{"spec":{"selinux":{"enable": true,` +
				`"options":{"allowedSystemProfiles":["container","net_container"]}}}}`,
		)
	}
}

func (e *e2e) logEnricherOnlyTestCase() {
	if !e.logEnricherEnabled {
		e.T().Skip("Skipping log-enricher related test")
	}

	e.enableLogEnricherInSpod()
}

// logEnricherBpfOnlyTestCase has its own switch: the BPF source only reports
// AppArmor denials (it hooks aa_audit), while the log enricher test case waits
// for seccomp audit lines, so it cannot pass wherever the BPF recorder runs.
func (e *e2e) logEnricherBpfOnlyTestCase() {
	if !e.bpfEnricherEnabled {
		e.T().Skip("Skipping log-enricher related test (BPF source)")
	}

	e.enableLogEnricherBpfInSpod()
}

func (e *e2e) logEnricherOnlyTestCaseWithFilters(enricherFilterJsonStr string) {
	if !e.logEnricherEnabled {
		e.T().Skip("Skipping log-enricher related test")
	}

	e.enableLogEnricherInSpodWithFilters(enricherFilterJsonStr)
}

func (e *e2e) jsonEnricherOnlyTestCase() {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping json-enricher related test")
	}

	e.enableJsonEnricherInSpod()
}

func (e *e2e) jsonEnricherOnlyTestCaseFileOptions(jsonLogFileName string,
	enricherFilterJsonStr string,
) {
	if !e.jsonEnricherEnabled {
		e.T().Skip("Skipping json-enricher FileOptions related test")
	}

	e.enableJsonEnricherInSpodFileOptions(jsonLogFileName, enricherFilterJsonStr)
}

func (e *e2e) enableLogEnricherBpfInSpod() {
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"enricher":{"logEnricherSource": "Bpf"}}}`, "--type=merge")
}

func (e *e2e) enableLogEnricherInSpod() {
	e.logf("Enable log-enricher in SPOD")
	// Remove the filters a previous test may have set, which would drop the
	// log lines this test waits for.
	e.patchSpod(`{"spec":{"enricher":{"enableJsonEnricher": false,"enableLogEnricher": true,` +
		`"logEnricherFilters": null}}}`)

	e.waitForTerminatingPods(5*time.Second, 5)

	for _, podName := range append(e.getSpodPodNames(), e.getSpodWebhookPodNames()...) {
		operatorName := config.OperatorName
		if !e.podRunning(podName, &operatorName, 5*time.Second, 5) {
			e.logf("Pod %s not running", podName)
			e.Fail("Failed to enable json-enricher in SPOD")
		}
	}
}

func (e *e2e) enableLogEnricherInSpodWithFilters(enricherFilterJsonStr string) {
	e.logf("Enable log-enricher in SPOD")
	e.patchSpod(
		"{\"spec\":{\"enricher\":{\"enableJsonEnricher\": false,\"enableLogEnricher\": true" +
			",\"logEnricherFilters\":" + enricherFilterJsonStr + "}}}",
	)
}

func (e *e2e) enableJsonEnricherInSpod() {
	e.logf("Enable json-enricher in SPOD with 20 second flush interval")
	e.patchSpod(`{"spec":{"enricher":{"enableLogEnricher": false, "enableJsonEnricher": true,
		"jsonEnricherOptions":{"auditLogIntervalSeconds":20}}}}`)

	if !e.checkExecWebhook(5*time.Second, 5) {
		e.Fail("Webhooks are not ready")
	}

	for _, podName := range append(e.getSpodPodNames(), e.getSpodWebhookPodNames()...) {
		operatorName := config.OperatorName
		if !e.podRunning(podName, &operatorName, 5*time.Second, 5) {
			e.logf("Pod %s not running", podName)
			e.Fail("Failed to enable json-enricher in SPOD")
		}
	}

	e.logf("Done waiting for the rollout restart")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLongOpTimeout)

	e.waitForTerminatingPods(5*time.Second, 5)
}

func (e *e2e) enableJsonEnricherInSpodFileOptions(logPath, enricherFilterJsonStr string) {
	e.logf("Enable json-enricher in SPOD with 20 second flush interval")

	jsonVolumeSource := fmt.Sprintf(
		`{\"hostPath\": {\"path\": \"%s\",\"type\": \"DirectoryOrCreate\"}}`,
		filepath.Dir(logPath),
	)

	patchOperatorJson := filepath.Join(e.T().TempDir(), "patch_operator.json")

	patchFile, fileErr := os.OpenFile(patchOperatorJson, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if fileErr != nil {
		e.Fail(fmt.Sprintf("Failed to open file '%s': %v", patchOperatorJson, fileErr))

		return
	}

	_, writeErr := fmt.Fprintf(
		patchFile,
		`{"data": {"json-enricher-log-volume-mount-path": "%s","json-enricher-log-volume-source.json":"%s"}}`,
		filepath.Dir(logPath),
		jsonVolumeSource,
	)
	if writeErr != nil {
		e.Fail(fmt.Sprintf("Failed to write file '%s': %v", patchOperatorJson, writeErr))

		return
	}

	fileCloseErr := patchFile.Close()
	if fileCloseErr != nil {
		// Igrore with log
		e.logf("Failed to close file '%s': %v", patchOperatorJson, fileCloseErr)
	}

	e.logf("Printing the patch file '%s'", patchOperatorJson)
	e.run("cat", patchOperatorJson)

	e.kubectlOperatorNS(
		"patch",
		"configmap",
		"security-profiles-operator-profile",
		"--patch-file",
		patchOperatorJson,
	)

	e.logf("Rollout restart deployment security-profiles-operator")

	e.kubectlOperatorNS("rollout", "restart", "deployment", "security-profiles-operator")

	e.waitForTerminatingPods(5*time.Second, 5)

	// This is required for all the restarts to complete
	for _, podName := range e.getOperatorPodNames() {
		operatorName := config.OperatorName
		if !e.podRunning(podName, &operatorName, 5*time.Second, 5) {
			e.logf("Pod %s not running", podName)
			e.Fail("Failed to restart SPO")
		}
	}

	e.logf("Done waiting for the rollout restart")

	e.patchSpod(
		fmt.Sprintf(`{"spec":{"enricher":{"enableLogEnricher": false,"enableJsonEnricher": true,
		"jsonEnricherOptions":{"auditLogIntervalSeconds":20,"auditLogPath": "%s"},"jsonEnricherFilters": "%s"}}}`,
			logPath, enricherFilterJsonStr),
	)

	e.logf("Patched the SPOD")
}

func (e *e2e) seccompOnlyTestCase() {
	if !e.testSeccomp {
		e.T().Skip("Skipping Seccomp-related test")
	}
}

func (e *e2e) bpfRecorderOnlyTestCase() {
	if !e.bpfRecorderEnabled {
		e.T().Skip("Skipping bpf recorder related test")
	}

	e.enableBpfRecorderInSpod()
}

func (e *e2e) enableBpfRecorderInSpod() {
	e.logf("Enable bpf recorder in SPOD")
	e.patchSpod(`{"spec":{"enricher":{"enableBpfRecorder": true}}}`)
}

func (e *e2e) enableMemoryOptimization() {
	e.logf("Enable memory optimization in SPOD")
	e.patchSpod(`{"spec":{"enableMemoryOptimization": true}}`)
}

func (e *e2e) disableMemoryOptimization() {
	e.logf("Disable memory optimization in SPOD")
	e.patchSpod(`{"spec":{"enableMemoryOptimization": false}}`)
}

func (e *e2e) deployRecordingSa(namespace string) {
	saTemplate := `
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      creationTimestamp: null
      name: recording-sa
      namespace: %s
`

	e.applyFromTemplate(saTemplate, namespace)
}

func (e *e2e) deployRecordingRole(namespace string) {
	roleTemplate := `
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      creationTimestamp: null
      name: recording
      namespace: %s
    rules:
    - apiGroups:
      - security.openshift.io
      resources:
      - securitycontextconstraints
      resourceNames:
      - privileged
      - anyuid
      verbs:
      - use
`

	e.applyFromTemplate(roleTemplate, namespace)
}

func (e *e2e) deployRecordingRoleBinding(namespace string) {
	roleBindingTemplate := `
    kind: RoleBinding
    apiVersion: rbac.authorization.k8s.io/v1
    metadata:
      labels:
        app: recording
      name: recording
      namespace: %s
    subjects:
    - kind: ServiceAccount
      name: recording-sa
    roleRef:
      kind: Role
      name: recording
      apiGroup: rbac.authorization.k8s.io
`

	e.applyFromTemplate(roleBindingTemplate, namespace)
}

func (e *e2e) applyFromTemplate(template, namespace string) {
	manifestFile := "templated-manifest.yaml"
	manifest := fmt.Sprintf(template, namespace)
	e.writeAndApply(manifest, manifestFile)
}

func (e *e2e) enableBindingHookInNs(ns string) {
	e.labelNs(ns, "spo.x-k8s.io/enable-binding")
}

func (e *e2e) enableRecordingHookInNs(ns string) {
	e.labelNs(ns, "spo.x-k8s.io/enable-recording")
}

func (e *e2e) labelNs(namespace, label string) {
	e.kubectl("label", "ns", namespace, "--overwrite", label+"=")
}

func (e *e2e) switchToNs(ns string) func() {
	nsManifest := "\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: " + ns

	e.logf("creating ns %s", ns)

	e.writeAndApply(nsManifest, ns+".yml")

	e.logf("switching to ns %s", ns)
	curNs := e.getCurrentContextNamespace(config.OperatorName)
	e.kubectl("config", "set-context", "--current", "--namespace", ns)

	return func() {
		e.logf("switching back to ns %s", curNs)
		e.kubectl("config", "set-context", "--current", "--namespace", curNs)
	}
}

//nolint:unparam // Even though we pass the same ns currently, it is still cleaner to pass it as a parameter
func (e *e2e) switchToRecordingNs(ns string) func() {
	retFunc := e.switchToNs(ns)
	e.enableRecordingHookInNs(ns)

	return retFunc
}

func (e *e2e) checkExecWebhook(interval time.Duration, maxTimes int) bool {
	err := poll(interval*time.Duration(maxTimes), interval, func() error {
		output := e.kubectlOperatorNS(
			"get",
			"mutatingwebhookconfigurations",
			"spo-mutating-webhook-configuration",
			`-o=jsonpath='{.webhooks[*].name}'`,
		)
		if !strings.Contains(output, "execmetadata.spo.io") {
			return fmt.Errorf("no execmetadata.spo.io webhook in %s", output)
		}

		return nil
	})
	if err != nil {
		e.logf("Unable to find execmetadata.spo.io in SPOD webhooks: %v", err)

		return false
	}

	return true
}

func (e *e2e) getPodNamesByLabel(labelMatcher string) []string {
	output := e.kubectlOperatorNS("get", "pods", "-l", labelMatcher,
		"--field-selector", "status.phase=Running,status.phase=Pending",
		`-o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'`)

	var filteredPodNames []string

	podNames := strings.SplitSeq(output, "\n")
	for name := range podNames {
		trimmedName := strings.Trim(name, "'")
		if trimmedName != "" {
			filteredPodNames = append(filteredPodNames, trimmedName)
		}
	}

	return filteredPodNames
}

func (e *e2e) getOperatorPodNames() []string {
	return e.getPodNamesByLabel("name=security-profiles-operator")
}

func (e *e2e) getSpodPodNames() []string {
	return e.getPodNamesByLabel("name=spod")
}

func (e *e2e) getSpodWebhookPodNames() []string {
	return e.getPodNamesByLabel("name=security-profiles-operator-webhook")
}

// Check if pod is running.
func (e *e2e) podRunning(
	name string,
	namespace *string,
	interval time.Duration,
	maxTimes int,
) bool {
	args := []string{"get", "pod", name, `-o=jsonpath='{.status.phase}'`}
	if namespace != nil {
		args = append(args, "-n", *namespace)
	}

	err := poll(interval*time.Duration(maxTimes), interval, func() error {
		output, err := e.kubectlCommand(args...)
		if err != nil {
			return fmt.Errorf("getting the status of pod %s: %w", name, err)
		}

		if phase := strings.Trim(output, "'"); phase != "Running" {
			return fmt.Errorf("pod %s is %s", name, phase)
		}

		return nil
	})
	if err != nil {
		e.logf("Pod %s is not running: %v", name, err)
		e.kubectl("describe", "pod", name)

		return false
	}

	return true
}

// Wait for terminating pods to be deleted.
func (e *e2e) waitForTerminatingPods(interval time.Duration, maxTimes int) {
	err := poll(interval*time.Duration(maxTimes), interval, func() error {
		output := e.kubectlOperatorNS(
			"get",
			"pods",
			`-o=jsonpath='{range .items[?(@.metadata.deletionTimestamp)]}{.metadata.name}{"\n"}{end}'`,
		)
		if terminating := strings.Trim(output, "'"); terminating != "" {
			return fmt.Errorf("terminating pods: %s", terminating)
		}

		return nil
	})
	if err != nil {
		// Not all waits for the rollout depend on it, so only log it.
		e.logf("Not all terminating pods got deleted: %v", err)

		return
	}

	e.logf("All terminating pods deleted")
}
