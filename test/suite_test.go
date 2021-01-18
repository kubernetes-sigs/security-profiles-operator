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
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/suite"
	"k8s.io/klog/v2/klogr"
	"k8s.io/release/pkg/command"
	"k8s.io/release/pkg/util"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	kindVersion = "v0.9.0"
	kindSHA512  = "e7152acf5fd7a4a56af825bda64b1b8343a1f91588f9b3ddd5420ae5c5a95577d87431f2e417a7e03dd23914e1da9bed855ec19d0c4602729b311baccb30bd7f" // nolint: lll
	kindImage   = "kindest/node:v1.20.0"
)

var (
	clusterType      = os.Getenv("E2E_CLUSTER_TYPE")
	containerRuntime = os.Getenv("CONTAINER_RUNTIME")
)

type e2e struct {
	suite.Suite
	kubectlPath string
	testImage   string
	pullPolicy  string
	logger      logr.Logger
	execNode    func(node string, args ...string) string
}

type kinde2e struct {
	e2e
	kindPath    string
	clusterName string
}

type openShifte2e struct {
	e2e
}

func TestSuite(t *testing.T) {
	fmt.Printf("cluster-type: %s\n", clusterType)
	switch {
	case clusterType == "" || strings.EqualFold(clusterType, "kind"):
		suite.Run(t, &kinde2e{
			e2e{
				logger:     klogr.New(),
				testImage:  config.OperatorName + ":latest",
				pullPolicy: "Never",
			},
			"", "",
		})
	case strings.EqualFold(clusterType, "openshift"):
		suite.Run(t, &openShifte2e{
			e2e{
				logger: klogr.New(),
				// Need to pull the image as it'll be uploaded to the cluster OCP
				// image registry and not on the nodes.
				pullPolicy: "Always",
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
	cwd, err := os.Getwd()
	e.Nil(err)

	parentCwd := filepath.Dir(cwd)
	e.Nil(os.Chdir(parentCwd))
	buildDir := filepath.Join(parentCwd, "build")
	e.Nil(os.MkdirAll(buildDir, 0o755))

	e.kindPath = filepath.Join(buildDir, "kind")
	e.downloadAndVerify(
		"https://github.com/kubernetes-sigs/kind/releases/download/"+
			kindVersion+"/kind-linux-amd64",
		e.kindPath, kindSHA512,
	)

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
	e.kubectl("wait", "--for", "condition=ready", "nodes", "--all")

	// Build and load the test image
	e.logf("Building operator container image")
	e.run("make", "image", "IMAGE="+e.testImage)
	e.logf("Loading container image into nodes")
	e.run(
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, e.testImage,
	)
}

// TearDownTest stops the kind cluster.
func (e *kinde2e) TearDownTest() {
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
	e.logf("Setting up suite")
	command.SetGlobalVerbose(true)
	// Override execNode function
	e.e2e.execNode = e.execNodeOCP
	cwd, err := os.Getwd()
	e.Nil(err)

	parentCwd := filepath.Dir(cwd)
	e.Nil(os.Chdir(parentCwd))
	buildDir := filepath.Join(parentCwd, "build")
	e.Nil(os.MkdirAll(buildDir, 0o755))

	e.kubectlPath, err = exec.LookPath("oc")
	e.Nil(err)

	e.logf("Using deployed OpenShift cluster")

	e.logf("Waiting for cluster to be ready")
	e.kubectl("wait", "--for", "condition=ready", "nodes", "--all")

	e.logf("Exposing registry")
	e.kubectl("patch", "configs.imageregistry.operator.openshift.io/cluster",
		"--patch", "{\"spec\":{\"defaultRoute\":true}}", "--type=merge")
	defer e.kubectl("patch", "configs.imageregistry.operator.openshift.io/cluster",
		"--patch", "{\"spec\":{\"defaultRoute\":false}}", "--type=merge")

	testImageRef := config.OperatorName + ":latest"

	// Build and load the test image
	e.logf("Building operator container image")
	e.run("make", "image", "IMAGE="+testImageRef)
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

func (e *openShifte2e) TearDownSuite() {
	e.kubectl(
		"delete", "imagestream", "-n", "openshift", config.OperatorName,
	)
}

func (e *openShifte2e) SetupTest() {
	e.logf("Setting up test")
}

// TearDownTest stops the kind cluster.
func (e *openShifte2e) TearDownTest() {
	e.logf("Tearing down test")
}

func (e *openShifte2e) execNodeOCP(node string, args ...string) string {
	return e.kubectl(
		"debug", "-q", fmt.Sprintf("node/%s", node), "--",
		"chroot", "/host", "/bin/bash", "-c",
		strings.Join(args, " "),
	)
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

func (e *e2e) kubectlOperatorNS(args ...string) {
	e.kubectl(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
}

func (e *e2e) logf(format string, a ...interface{}) {
	e.logger.Info(fmt.Sprintf(format, a...))
}

func (e *e2e) selinuxtOnlyTestCase() {
	// TODO(jaosorior): Come up with better way to assert if a cluster
	// supports SELinux or not.
	if !strings.EqualFold(clusterType, "openshift") {
		e.T().Skip("Skipping SELinux-related test from non-OpenShift cluster")
	}
}
