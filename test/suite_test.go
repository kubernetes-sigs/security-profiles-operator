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
)

const (
	kindVersion      = "v0.10.0"
	kindImage        = "kindest/node:v1.20.2"
	kindDarwinSHA512 = "f2da2d9695ef6d26ff7183f764506223b605bc4638f04742184622ab41599988d0489a54d92ccbad90a5420e47e0868350654d3f8851e0c9afb0fe3539557e00" // nolint: lll
	kindLinuxSHA512  = "1d2ef9f377ed513850dfd5028c80f3fefd7e3f28e3fc6050593c8a3894b74a40b9761f401ccf44d5aa199e9c753bbb9c1ffb51319f4864a1a2ba184d1574d242" // nolint: lll
)

var (
	clusterType                     = os.Getenv("E2E_CLUSTER_TYPE")
	envSkipBuildImages              = os.Getenv("E2E_SKIP_BUILD_IMAGES")
	envTestImage                    = os.Getenv("E2E_SPO_IMAGE")
	envSelinuxTestsEnabled          = os.Getenv("E2E_TEST_SELINUX")
	envSeccompTestsEnabled          = os.Getenv("E2E_TEST_SECCOMP")
	envProfileRecordingTestsEnabled = os.Getenv("E2E_TEST_PROFILE_RECORDING")
	containerRuntime                = os.Getenv("CONTAINER_RUNTIME")
)

const (
	clusterTypeKind      = "kind"
	clusterTypeVanilla   = "vanilla"
	clusterTypeOpenShift = "openshift"
)

type e2e struct {
	suite.Suite
	kubectlPath          string
	testImage            string
	selinuxdImage        string
	pullPolicy           string
	selinuxEnabled       bool
	testSeccomp          bool
	testProfileRecording bool
	logger               logr.Logger
	execNode             func(node string, args ...string) string
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
// nolint:paralleltest
func TestSuite(t *testing.T) {
	fmt.Printf("cluster-type: %s\n", clusterType)
	fmt.Printf("container-runtime: %s\n", containerRuntime)

	testImage := envTestImage
	selinuxEnabled, err := strconv.ParseBool(envSelinuxTestsEnabled)
	if err != nil {
		selinuxEnabled = false
	}
	testSeccomp, err := strconv.ParseBool(envSeccompTestsEnabled)
	if err != nil {
		testSeccomp = true
	}
	testProfileRecording, err := strconv.ParseBool(envProfileRecordingTestsEnabled)
	if err != nil {
		testProfileRecording = false
	}

	selinuxdImage := "quay.io/jaosorior/selinuxd"
	switch {
	case clusterType == "" || strings.EqualFold(clusterType, clusterTypeKind):
		if testImage == "" {
			testImage = config.OperatorName + ":latest"
		}
		suite.Run(t, &kinde2e{
			e2e{
				logger:               klogr.New(),
				pullPolicy:           "Never",
				testImage:            testImage,
				selinuxEnabled:       selinuxEnabled,
				testSeccomp:          testSeccomp,
				testProfileRecording: testProfileRecording,
				selinuxdImage:        selinuxdImage,
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
				pullPolicy:           "Always",
				testImage:            testImage,
				selinuxEnabled:       selinuxEnabled,
				testSeccomp:          testSeccomp,
				testProfileRecording: testProfileRecording,
				selinuxdImage:        selinuxdImage,
			},
			skipBuildImages,
			skipPushImages,
		})
	case strings.EqualFold(clusterType, clusterTypeVanilla):
		if testImage == "" {
			testImage = "localhost/" + config.OperatorName + ":latest"
		}
		selinuxdImage = "quay.io/jaosorior/selinuxd-fedora"
		suite.Run(t, &vanilla{
			e2e{
				logger:               klogr.New(),
				pullPolicy:           "Never",
				testImage:            testImage,
				selinuxEnabled:       selinuxEnabled,
				testSeccomp:          testSeccomp,
				testProfileRecording: testProfileRecording,
				selinuxdImage:        selinuxdImage,
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
	// Override execNode function
	e.e2e.execNode = e.execNodeKind
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

	cmd := exec.Command( // nolint: gosec
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
	e.kubectl("wait", "--for", "condition=ready", "nodes", "--all", "--timeout=120s")

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
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, "quay.io/jaosorior/selinuxd",
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

func (e *openShifte2e) SetupSuite() {
	var err error
	e.logf("Setting up suite")
	command.SetGlobalVerbose(true)
	// Override execNode function
	e.e2e.execNode = e.execNodeOCP
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

func (e *vanilla) SetupSuite() {
	var err error
	e.logf("Setting up suite")
	e.setWorkDir()

	e.e2e.execNode = e.execNodeVanilla
	e.kubectlPath, err = exec.LookPath("kubectl")
	e.Nil(err)
}

func (e *vanilla) SetupTest() {
	e.run(containerRuntime, "pull", e.selinuxdImage)
}

func (e *vanilla) TearDownTest() {
}

func (e *vanilla) execNodeVanilla(node string, args ...string) string {
	return e.run(args[0], args[1:]...)
}

func (e *e2e) setWorkDir() string {
	cwd, err := os.Getwd()
	e.Nil(err)

	parentCwd := filepath.Dir(cwd)
	e.Nil(os.Chdir(parentCwd))
	return parentCwd
}

func (e *e2e) run(cmd string, args ...string) string {
	output, err := command.New(cmd, args...).RunSuccessOutput()
	e.Nil(err)
	return output.OutputTrimNL()
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
			"run", "--rm", "-i", "--restart=Never",
			"--image=registry.fedoraproject.org/fedora-minimal:latest",
		}, args...)...,
	)
}

func (e *e2e) kubectlRunOperatorNS(args ...string) string {
	return e.kubectlRun(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
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

func (e *e2e) selinuxtOnlyTestCase() {
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

func (e *e2e) seccompOnlyTestCase() {
	if !e.testSeccomp {
		e.T().Skip("Skipping Seccomp-related test")
	}
}

func (e *e2e) profileRecordingTestCase() {
	if !e.testProfileRecording {
		e.T().Skip("Skipping Profile-Recording-related test")
	}
}
