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
	"k8s.io/klog/v2/klogr"
	"sigs.k8s.io/release-utils/command"
	"sigs.k8s.io/release-utils/util"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	spoutil "sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	kindVersion      = "v0.15.0"
	kindImage        = "kindest/node:v1.25.0@sha256:428aaa17ec82ccde0131cb2d1ca6547d13cf5fdabcc0bbecf749baa935387cbf"
	kindDarwinSHA512 = "f9b4e1ef345d831c19014cce1db42949ff68452590759b4802d183063e5280dfb1c92fd9626d9c952c60d9e440e9872c97525bd9a3b4ba53e43c00762d1e9980" //nolint:lll // full length SHA
	kindLinuxSHA512  = "9c397eb7cc64f7fb0ac8d686ebf3836aaf485a1a480baa23b91a5167aa1d30b16a730de32910f9463d2028e01d56412bbfb3e9afdaa94b7eb19eef21c650e973" //nolint:lll // full length SHA
)

var (
	clusterType                  = os.Getenv("E2E_CLUSTER_TYPE")
	envSkipBuildImages           = os.Getenv("E2E_SKIP_BUILD_IMAGES")
	envTestImage                 = os.Getenv("E2E_SPO_IMAGE")
	spodConfig                   = os.Getenv("E2E_SPOD_CONFIG")
	envSkipFlakyTests            = os.Getenv("E2E_SKIP_FLAKY_TESTS")
	envSkipNamespacedTests       = os.Getenv("E2E_SKIP_NAMESPACED_TESTS")
	envSelinuxTestsEnabled       = os.Getenv("E2E_TEST_SELINUX")
	envLogEnricherTestsEnabled   = os.Getenv("E2E_TEST_LOG_ENRICHER")
	envSeccompTestsEnabled       = os.Getenv("E2E_TEST_SECCOMP")
	envBpfRecorderTestsEnabled   = os.Getenv("E2E_TEST_BPF_RECORDER")
	envWebhookConfigTestsEnabled = os.Getenv("E2E_TEST_WEBHOOK_CONFIG")
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

	if operatorManifest == "" {
		operatorManifest = defaultManifest
	}

	selinuxdImage := "quay.io/security-profiles-operator/selinuxd"
	switch {
	case clusterType == "" || strings.EqualFold(clusterType, clusterTypeKind):
		if testImage == "" {
			testImage = config.OperatorName + ":latest"
		}
		suite.Run(t, &kinde2e{
			e2e{
				logger:              klogr.New(),
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
				logger: klogr.New(),
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
				skipFlakyTests:      skipFlakyTests,
			},
			skipBuildImages,
			skipPushImages,
		})
	case strings.EqualFold(clusterType, clusterTypeVanilla):
		if testImage == "" {
			testImage = "localhost/" + config.OperatorName + ":latest"
		}
		selinuxdImage = "quay.io/security-profiles-operator/selinuxd-fedora"
		suite.Run(t, &vanilla{
			e2e{
				logger:              klogr.New(),
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
	e.Nil(os.MkdirAll(buildDir, 0o755))

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
	e.Nil(err)
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
	e.Nil(cmd.Run())

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
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, "quay.io/security-profiles-operator/selinuxd",
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
	e.Nil(err)

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
		"debug", "-q", fmt.Sprintf("node/%s", node), "--",
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
	e.Nil(err)
}

func (e *vanilla) SetupTest() {
	e.logf("Setting up test")
	if e.selinuxEnabled {
		e.run(containerRuntime, "pull", e.selinuxdImage)
	}
}

func (e *vanilla) TearDownTest() {
}

func (e *vanilla) execNodeVanilla(node string, args ...string) string {
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
	e.Nil(err)

	parentCwd := filepath.Dir(cwd)
	e.Nil(os.Chdir(parentCwd))
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
	e.Nil(err)
	if output != nil {
		return output.OutputTrimNL()
	}
	return ""
}

func (e *e2e) runFailure(cmd string, args ...string) string {
	output, err := command.New(cmd, args...).Run()
	e.Nil(err)
	e.False(output.Success())
	return output.Error()
}

func (e *e2e) downloadAndVerify(url, binaryPath, sha512 string) {
	if !util.Exists(binaryPath) {
		e.logf("Downloading %s", binaryPath)
		e.run("curl", "-o", binaryPath, "-fL", url)
		e.Nil(os.Chmod(binaryPath, 0o700))
		e.verifySHA512(binaryPath, sha512)
	}
}

func (e *e2e) verifySHA512(binaryPath, sha512 string) {
	e.Nil(command.New("sha512sum", binaryPath).
		Pipe("grep", sha512).
		RunSilentSuccess(),
	)
}

func (e *e2e) kubectl(args ...string) string {
	return e.run(e.kubectlPath, args...)
}

func (e *e2e) kubectlFailure(args ...string) string {
	return e.runFailure(e.kubectlPath, args...)
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
	curlBaseCMD = "curl -ksfL --retry 5 --retry-delay 3 --show-error "
	curlCMD     = curlBaseCMD + "-H \"Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`\" "
	metricsURL  = "https://metrics.security-profiles-operator.svc.cluster.local/"
	curlSpodCMD = curlCMD + metricsURL + "metrics-spod"
	curlCtrlCMD = curlCMD + metricsURL + "metrics"
)

func (e *e2e) getSpodMetrics() string {
	rand.Seed(time.Now().UnixNano())
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))] //nolint:gosec // fine in tests
	}
	// Sometimes the metrics command does not output anything in CI. We fix
	// that by retrying the metrics retrieval several times.
	var output string
	if err := spoutil.Retry(func() error {
		output = e.kubectlRunOperatorNS("pod-"+string(b), "--", "bash", "-c", curlSpodCMD)
		if len(strings.Split(output, "\n")) > 1 {
			return nil
		}
		output = ""
		return fmt.Errorf("no metrics output yet")
	}, func(err error) bool {
		e.logf("retry on error: %s", err)
		return true
	}); err != nil {
		e.Failf("unable to retrieve SPOD metrics", "error: %s", err)
	}
	return output
}

func (e *e2e) waitFor(args ...string) {
	e.kubectl(
		append([]string{"wait", "--timeout", defaultWaitTimeout, "--for"}, args...)...,
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
	nsManifest := fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %s`, ns)

	e.logf("creating ns %s", ns)
	deleteFn := e.writeAndApply(nsManifest, fmt.Sprintf("%s.yml", ns))
	defer deleteFn()

	e.logf("switching to ns %s", ns)
	curNs := e.getCurrentContextNamespace(config.OperatorName)
	e.kubectl("config", "set-context", "--current", "--namespace", ns)
	return func() {
		e.logf("switching back to to ns %s", curNs)
		e.kubectl("config", "set-context", "--current", "--namespace", curNs)
	}
}

//nolint:unparam // Even though we pass the same ns currently, it is still cleaner to pass it as a parameter
func (e *e2e) switchToRecordingNs(ns string) func() {
	retFunc := e.switchToNs(ns)
	e.enableRecordingHookInNs(ns)
	return retFunc
}
