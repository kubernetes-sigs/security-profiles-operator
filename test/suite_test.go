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
	kindVersion      = "v0.27.0"
	kindImage        = "kindest/node:v1.32.2@sha256:f226345927d7e348497136874b6d207e0b32cc52154ad8323129352923a3142f"
	kindDarwinSHA512 = "ccd2413c2293a80f4944937a0855fc800e5fe1ad41baea0b528ed390cdce473f076c1c0fd61f0d24adec87589878ab136377cd4a546c19a349bf140ecd7df5a3" //nolint:lll // full length SHA
	kindLinuxSHA512  = "7b744426a5a8cb9908eda1cc9af3308deb0318cc589a7fc864f4717815839644e31b24b351ee46d14422d990b9eb3ab10a25063c97a76973534d6d112631000c" //nolint:lll // full length SHA
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
	envJsonEnricherTestsEnabled  = os.Getenv("E2E_TEST_JSON_ENRICHER")
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
	jsonEnricherEnabled   bool
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
				jsonEnricherEnabled: jsonEnricherEnabled,
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
				jsonEnricherEnabled: jsonEnricherEnabled,
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
				jsonEnricherEnabled: jsonEnricherEnabled,
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
	e.execNode = e.execNodeKind
	e.waitForReadyPods = e.waitForReadyPodsKind
	e.deployCertManager = e.deployCertManagerKind
	e.setupRecordingSa = e.deployRecordingSa
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
	e.execNode = e.execNodeOCP
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
	e.execNode = e.execNodeVanilla
	e.kubectlPath, err = exec.LookPath("kubectl")
	e.waitForReadyPods = e.waitForReadyPodsVanilla
	e.deployCertManager = e.deployCertManagerVanilla
	e.setupRecordingSa = e.deployRecordingSa
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
	output, err := e.runCommand(cmd, args...)
	e.NoError(err)

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

func (e *e2e) kubectlCommand(args ...string) (string, error) {
	return e.runCommand(e.kubectlPath, args...)
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

func (e *e2e) enableLogEnricherInSpod() {
	e.logf("Enable log-enricher in SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"enableJsonEnricher": false,"enableLogEnricher": true}}`, "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLogEnricherOpTimeout)
}

func (e *e2e) enableLogEnricherInSpodWithFilters(enricherFilterJsonStr string) {
	e.logf("Enable log-enricher in SPOD")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		"{\"spec\":{\"enableJsonEnricher\": false,\"enableLogEnricher\": true"+
			",\"logEnricherFilters\":"+enricherFilterJsonStr+"}}", "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLogEnricherOpTimeout)
}

func (e *e2e) enableJsonEnricherInSpod() {
	e.logf("Enable json-enricher in SPOD with 20 second flush interval")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		`{"spec":{"enableLogEnricher": false, "enableJsonEnricher": true,
		"jsonEnricherOptions":{"auditLogIntervalSeconds":20}}}`, "--type=merge")

	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	if !e.checkExecWebhook(5*time.Second, 5) {
		e.Fail("Webhooks are not ready")
	}

	for _, podName := range append(e.getSpodPodNames(), e.getSpodWebhookPodNames()...) {
		if !e.podRunning(podName, config.OperatorName, 5*time.Second, 5) {
			e.logf("Pod %s not running", podName)
			e.Fail("Failed to enable json-enricher in SPOD")
		}
	}

	e.logf("Done waiting for the rollout restart")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLogEnricherOpTimeout)

	e.waitForTerminatingPods(5*time.Second, 5)
}

func (e *e2e) enableJsonEnricherInSpodFileOptions(logPath, enricherFilterJsonStr string) {
	e.logf("Enable json-enricher in SPOD with 20 second flush interval")

	jsonVolumeSource := fmt.Sprintf(`{\"hostPath\": {\"path\": \"%s\",\"type\": \"DirectoryOrCreate\"}}`,
		filepath.Dir(logPath))

	patchOperatorJson := "patch_operator.json"
	_ = os.Remove(patchOperatorJson)

	patchFile, fileErr := os.OpenFile(patchOperatorJson, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if fileErr != nil {
		e.Fail(fmt.Sprintf("Failed to open file '%s': %v", patchOperatorJson, fileErr))

		return
	}

	_, writeErr := fmt.Fprintf(patchFile,
		`{"data": {"json-enricher-log-volume-mount-path": "%s","json-enricher-log-volume-source.json":"%s"}}`,
		filepath.Dir(logPath), jsonVolumeSource)
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

	e.kubectlOperatorNS("patch", "configmap", "security-profiles-operator-profile", "--patch-file", patchOperatorJson)

	e.logf("Rollout restart deployment security-profiles-operator")

	e.kubectlOperatorNS("rollout", "restart", "deployment", "security-profiles-operator")

	e.waitForTerminatingPods(5*time.Second, 5)

	// This is required for all the restarts to complete
	for _, podName := range e.getOperatorPodNames() {
		if !e.podRunning(podName, config.OperatorName, 5*time.Second, 5) {
			e.logf("Pod %s not running", podName)
			e.Fail("Failed to restart SPO")
		}
	}

	e.logf("Done waiting for the rollout restart")

	_ = os.Remove(patchOperatorJson)

	e.kubectlOperatorNS("patch", "spod", "spod", "-p",
		fmt.Sprintf(`{"spec":{"enableLogEnricher": false,"enableJsonEnricher": true,
		"jsonEnricherOptions":{"auditLogIntervalSeconds":20,"auditLogPath": "%s"},"jsonEnricherFilters": "%s"}}`,
			logPath, enricherFilterJsonStr), "--type=merge")

	e.logf("Patched the SPOD")

	time.Sleep(defaultWaitTime * 2)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLogEnricherOpTimeout)

	if !e.checkExecWebhook(5*time.Second, 5) {
		e.Fail("Webhooks are not ready")
	}

	for _, podName := range append(e.getSpodPodNames(), e.getSpodWebhookPodNames()...) {
		if !e.podRunning(podName, config.OperatorName, 5*time.Second, 5) {
			e.logf("Pod %s not running", podName)
			e.Fail("Failed to enable json-enricher in SPOD")
		}
	}
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

func (e *e2e) checkExecWebhook(interval time.Duration, maxTimes int) bool {
	for range maxTimes {
		output := e.kubectlOperatorNS("get", "mutatingwebhookconfigurations", "spo-mutating-webhook-configuration",
			`-o=jsonpath='{.webhooks[*].name}'`)
		if !strings.Contains(output, "execmetadata.spo.io") {
			time.Sleep(interval)
		} else {
			return true
		}
	}

	e.logf("Unable to find execmetadata.spo.io in SPOD webhooks")

	return false
}

func (e *e2e) getPodNamesByLabel(labelMatcher string) []string {
	output := e.kubectlOperatorNS("get", "pods", "-l", labelMatcher,
		"--field-selector", "status.phase=Running,status.phase=Pending",
		`-o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'`)

	var filteredPodNames []string

	podNames := strings.Split(output, "\n")
	for _, name := range podNames {
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
func (e *e2e) podRunning(name, namespace string, interval time.Duration, maxTimes int) bool {
	for range maxTimes {
		output, err := e.kubectlCommand("get", "pod", name, "-n", namespace, `-o=jsonpath='{.status.phase}'`)
		//nolint:gocritic // If else is better.
		if err != nil {
			e.logf("Unable to get pod status for pod %s: %v", name, err)
			time.Sleep(interval)
		} else if strings.Trim(output, "'") != "Running" {
			e.logf("Pod is still not running %s: %s", name, output)
			time.Sleep(interval)
		} else {
			return true
		}
	}

	e.logf("Pod %s is not running after checking %d times", name, maxTimes)
	e.kubectl("describe", "pod", name)

	return false
}

func (e *e2e) waitForTerminatingPods(interval time.Duration, maxTimes int) {
	for range maxTimes {
		output := e.kubectlOperatorNS("get", "pods",
			`-o=jsonpath='{range .items[?(@.metadata.deletionTimestamp)]}{.metadata.name}{"\n"}{end}'`)
		if strings.Trim(output, "'") != "" {
			e.logf("Terminating pods found: %s", output)
			time.Sleep(interval)
		} else {
			e.logf("All teminating pods deleted")

			return
		}
	}

	e.logf("All Terminating Pods are not deleted")
}
