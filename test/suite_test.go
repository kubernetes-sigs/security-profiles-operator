/*
Copyright 2020 The Kubernetes Authors.

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
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/suite"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/release-utils/command"
	"sigs.k8s.io/release-utils/util"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	spoutil "sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	kindVersion      = "v0.26.0"
	kindImage        = "kindest/node:v1.32.0@sha256:c48c62eac5da28cdadcf560d1d8616cfa6783b58f0d94cf63ad1bf49600cb027"
	kindDarwinSHA512 = "e40861aa6c9ac9ac36da5067272f5e9b9548c0f37d00fe0aaa52a3bd92f3608fb1155bd4e598083ff77cb38c8e2633ccb4138667912f34be783af34c055804f2" //nolint:lll // full length SHA
	kindLinuxSHA512  = "15ba3777f5c4f17b3cc90eee62549cb42c6106a40fe115c8524d72f3a8601362d50890c52fc2561d0fe77e15865a274ca67600903ef2dde00780aad1dccffc1e" //nolint:lll // full length SHA
)

var (
	clusterType                  = os.Getenv("E2E_CLUSTER_TYPE")
	envSkipBuildImages           = os.Getenv("E2E_SKIP_BUILD_IMAGES")
	envTestImage                 = os.Getenv("E2E_SPO_IMAGE")
	envSelinuxdTestImage         = os.Getenv("E2E_SELINUXD_IMAGE")
	spodConfig                   = os.Getenv("E2E_SPOD_CONFIG")
	envSkipFlakyTests            = os.Getenv("E2E_SKIP_FLAKY_TESTS")
	envSkipNamespacedTests       = os.Getenv("E2E_SKIP_NAMESPACED_TESTS")
	envSelinuxTestsEnabled       = os.Getenv("E2E_TEST_SELINUX")
	envLogEnricherTestsEnabled   = os.Getenv("E2E_TEST_LOG_ENRICHER")
	envSeccompTestsEnabled       = os.Getenv("E2E_TEST_SECCOMP")
	envBpfRecorderTestsEnabled   = os.Getenv("E2E_TEST_BPF_RECORDER")
	envWebhookConfigTestsEnabled = os.Getenv("E2E_TEST_WEBHOOK_CONFIG")
	envWebhookHTTPTestsEnabled   = os.Getenv("E2E_TEST_WEBHOOK_HTTP")
	envMetricsHTTPTestsEnabled   = os.Getenv("E2E_TEST_METRICS_HTTP")
	containerRuntime             = os.Getenv("CONTAINER_RUNTIME")
	nodeRootfsPrefix             = os.Getenv("NODE_ROOTFS_PREFIX")
	operatorManifest             = os.Getenv("OPERATOR_MANIFEST")
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
	containerRuntime      string
	kubectlPath           string
	testImage             string
	selinuxdImage         string
	pullPolicy            string
	spodConfig            string
	nodeRootfsPrefix      string
	operatorManifest      string
	selinuxEnabled        bool
	logEnricherEnabled    bool
	testSeccomp           bool
	bpfRecorderEnabled    bool
	skipNamespacedTests   bool
	skipFlakyTests        bool
	testWebhookConfig     bool
	testWebhookHTTP       bool
	testMetricsHTTP       bool
	singleNodeEnvironment bool
	logger                logr.Logger
	execNode              func(node string, args ...string) string
	waitForReadyPods      func()
	deployCertManager     func()
	setupRecordingSa      func(namespace string)
}

func defaultWaitForReadyPods(e *e2e) {
	e.logf("Waiting for all pods to become ready")
	e.waitFor("condition=ready", "pods", "--all", "--all-namespaces")
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
	testSeccomp, err := strconv.ParseBool(envSeccompTestsEnabled)
	if err != nil {
		testSeccomp = true
	}
	bpfRecorderEnabled, err := strconv.ParseBool(envBpfRecorderTestsEnabled)
	if err != nil {
		bpfRecorderEnabled = false
	}

	skipNamespacedTests, err := strconv.ParseBool(envSkipNamespacedTests)
	if err != nil {
		skipNamespacedTests = false
	}

	skipFlakyTests, err := strconv.ParseBool(envSkipFlakyTests)
	if err != nil {
		skipFlakyTests = true
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
				testSeccomp:         testSeccomp,
				selinuxdImage:       selinuxdImage,
				bpfRecorderEnabled:  bpfRecorderEnabled,
				skipNamespacedTests: skipNamespacedTests,
				operatorManifest:    operatorManifest,
				testWebhookConfig:   testWebhookConfig,
				testWebhookHTTP:     testWebhookHTTP,
				testMetricsHTTP:     testMetricsHTTP,
				skipFlakyTests:      skipFlakyTests,
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
				testSeccomp:         testSeccomp,
				selinuxdImage:       selinuxdImage,
				bpfRecorderEnabled:  bpfRecorderEnabled,
				skipNamespacedTests: skipNamespacedTests,
				operatorManifest:    operatorManifest,
				testWebhookConfig:   testWebhookConfig,
				testWebhookHTTP:     testWebhookHTTP,
				testMetricsHTTP:     testMetricsHTTP,
				skipFlakyTests:      skipFlakyTests,
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
				testSeccomp:         testSeccomp,
				selinuxdImage:       selinuxdImage,
				bpfRecorderEnabled:  bpfRecorderEnabled,
				skipNamespacedTests: skipNamespacedTests,
				operatorManifest:    operatorManifest,
				testWebhookConfig:   testWebhookConfig,
				testWebhookHTTP:     testWebhookHTTP,
				testMetricsHTTP:     testMetricsHTTP,
				skipFlakyTests:      skipFlakyTests,
				// NOTE(jaosorior): Our current vanilla jobs are
				// single-node only.
				singleNodeEnvironment: true,
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
	e.e2e.execNode = e.execNodeKind
	e.e2e.waitForReadyPods = e.waitForReadyPodsKind
	e.e2e.deployCertManager = e.deployCertManagerKind
	e.e2e.setupRecordingSa = e.deployRecordingSa
	parentCwd := e.setWorkDir()
	buildDir := filepath.Join(parentCwd, "build")
	e.Require().NoError(os.MkdirAll(buildDir, 0o755))

	e.kindPath = filepath.Join(buildDir, "kind")
	SHA512 := ""
	kindOS := ""
	switch runtime.GOOS {
	case "darwin":
		SHA512 = kindDarwinSHA512
		kindOS = "kind-darwin-amd64"
	case "linux":
		SHA512 = kindLinuxSHA512
		kindOS = "kind-linux-amd64"
	}

	e.downloadAndVerify(fmt.Sprintf("https://github.com/kubernetes-sigs/kind/releases/download/%s/%s",
		kindVersion, kindOS), e.kindPath, SHA512)

	var err error
	e.kubectlPath, err = exec.LookPath("kubectl")
	e.updateManifest(e.operatorManifest, "value: .*quay.io/.*/selinuxd.*", "value: "+e.selinuxdImage)
	e.NoError(err)
}

// SetupTest starts a fresh kind cluster for each test.
func (e *kinde2e) SetupTest() {
	// Deploy the cluster
	e.logf("Deploying the cluster")
	e.clusterName = fmt.Sprintf("spo-e2e-%d", time.Now().Unix())

	cmd := exec.Command( //nolint:gosec // fine in tests
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

func (e *kinde2e) execNodeKind(node string, args ...string) string {
	return e.run(containerRuntime, append([]string{"exec", node}, args...)...)
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
	e.e2e.execNode = e.execNodeOCP
	e.e2e.waitForReadyPods = e.waitForReadyPodsOCP
	e.e2e.deployCertManager = e.deployCertManagerOCP
	e.e2e.setupRecordingSa = e.deployRecordingSaOcp
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
		"get", "imagestreamtag", "-n", "openshift", testImageRef, "-o", "jsonpath={.image.dockerImageReference}",
	)
}

func (e *openShifte2e) execNodeOCP(node string, args ...string) string {
	return e.kubectl(
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
	e.e2e.execNode = e.execNodeVanilla
	e.kubectlPath, err = exec.LookPath("kubectl")
	e.e2e.waitForReadyPods = e.waitForReadyPodsVanilla
	e.e2e.deployCertManager = e.deployCertManagerVanilla
	e.e2e.setupRecordingSa = e.deployRecordingSa
	e.updateManifest(e.operatorManifest, "value: .*quay.io/.*/selinuxd.*", "value: "+e.selinuxdImage)
	e.NoError(err)
}

func (e *vanilla) SetupTest() {
	e.logf("Setting up test")
	if e.selinuxEnabled {
		e.run(containerRuntime, "pull", e.selinuxdImage)
	}
}

func (e *vanilla) TearDownTest() {
}

func (e *vanilla) execNodeVanilla(_ string, args ...string) string {
	return e.run(args[0], args[1:]...)
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

// Use the breakPoint function at a point where you want to pause a test.
// The test will log a tempfile created bythe breakPoint() function and
// wait for the file to be removed by the test user.
//
// (jhrozek): Maybe we should set a global timeout to continue?
func (e *e2e) breakPoint() { //nolint:unused // used on demand
	tmpfile, err := os.CreateTemp("", "testBreakpoint*.lock")
	if err != nil {
		e.logger.Error(err, "Can't create breakpoint file")
		return
	}
	tmpfile.Close()

	delChannel := make(chan struct{})
	go func() {
		for {
			_, err := os.Stat(tmpfile.Name())
			if err == nil {
				e.logger.Info("breakpoint: File exists, waiting 5 secs", "fileName", tmpfile.Name())
				time.Sleep(time.Second * 5)
				continue
			}
			break
		}
		delChannel <- struct{}{}
	}()

	<-delChannel
}

func (e *e2e) run(cmd string, args ...string) string {
	output, err := command.New(cmd, args...).RunSuccessOutput()
	e.NoError(err)
	if output != nil {
		return output.OutputTrimNL()
	}
	return ""
}

func (e *e2e) downloadAndVerify(url, binaryPath, sha512 string) {
	if !util.Exists(binaryPath) {
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
	return e.run(e.kubectlPath, args...)
}

func (e *e2e) kubectlOperatorNS(args ...string) string {
	return e.kubectl(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
}

func (e *e2e) kubectlRun(args ...string) string {
	return e.kubectl(
		append([]string{
			"run",
			"--pod-running-timeout=5m",
			"--rm",
			"-i",
			"--restart=Never",
			"--image=registry.fedoraproject.org/fedora-minimal:latest",
		}, args...)...,
	)
}

func (e *e2e) kubectlRunOperatorNS(args ...string) string {
	return e.kubectlRun(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
}

const (
	curlBaseCMD    = "curl -ksL --retry 5 --retry-delay 3 --show-error "
	headerAuth     = "-H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" "
	curlCMD        = curlBaseCMD + headerAuth + "-f "
	curlHTTPVerCMD = curlBaseCMD + headerAuth + "-I -w '%{http_version}\n' -o/dev/null "
	metricsURL     = "https://metrics.security-profiles-operator.svc.cluster.local/"
	webhooksURL    = "https://webhook-service.security-profiles-operator.svc.cluster.local/"
	curlSpodCMD    = curlCMD + metricsURL + "metrics-spod"
	curlCtrlCMD    = curlCMD + metricsURL + "metrics"
)

func (e *e2e) runAndRetryPodCMD(podCMD string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	maxTries := 0
	// Sometimes the metrics command does not output anything in CI. We fix
	// that by retrying the metrics retrieval several times.
	var output string
	if err := spoutil.Retry(func() error {
		output = e.kubectlRunOperatorNS("pod-"+string(b), "--", "bash", "-c", podCMD)
		if len(strings.Split(output, "\n")) > 1 {
			return nil
		}
		output = ""
		return errors.New("no output from pod command")
	}, func(err error) bool {
		e.logf("retry on error: %s", err)
		if maxTries < 3 {
			maxTries++
			return true
		}
		return false
	}); err != nil {
		e.Failf("unable to run pod command", "error: %s", err)
	}
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

func (e *e2e) logf(format string, a ...interface{}) {
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
		e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableSelinux": true}}`, "--type=merge")
		e.kubectlOperatorNS("patch", "spod", "spod", "-p",
			`{"spec":{"selinuxOptions":{"allowedSystemProfiles":["container","net_container"]}}}`,
			"--type=merge")

		time.Sleep(defaultWaitTime)
		e.waitInOperatorNSFor("condition=ready", "spod", "spod")

		e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultSelinuxOpTimeout)
	}
}

func (e *e2e) logEnricherOnlyTestCase() {
	if !e.logEnricherEnabled {
		e.T().Skip("Skipping log-enricher related test")
	}

	e.enableLogEnricherInSpod()
}

func (e *e2e) enableLogEnricherInSpod() {
	e.logf("Enable log-enricher in SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableLogEnricher": true}}`, "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLogEnricherOpTimeout)
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

func (e *e2e) singleNodeTestCase() {
	if !e.singleNodeEnvironment {
		e.T().Skip("Skipping test because we're in a multi-node environment.")
	}
}

func (e *e2e) enableBpfRecorderInSpod() {
	e.logf("Enable bpf recorder in SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableBpfRecorder": true}}`, "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)
}

func (e *e2e) enableMemoryOptimization() {
	e.logf("Enable memory optimization in SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableMemoryOptimization": true}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)
}

func (e *e2e) disableMemoryOptimization() {
	e.logf("Enable memory optimization in SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableMemoryOptimization": false}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)
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
	deleteSaFn := e.writeAndApply(manifest, manifestFile)
	deleteSaFn()
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
	deleteFn := e.writeAndApply(nsManifest, ns+".yml")
	defer deleteFn()

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
