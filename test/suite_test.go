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
	kindImage   = "kindest/node:v1.19.1"
	testImage   = config.OperatorName + ":latest"
)

type e2e struct {
	suite.Suite
	kindPath    string
	kubectlPath string
	clusterName string
	logger      logr.Logger
}

func TestSuite(t *testing.T) {
	suite.Run(t, &e2e{logger: klogr.New()})
}

// SetupSuite downloads kind and searches for kubectl in $PATH.
func (e *e2e) SetupSuite() {
	e.logf("Setting up suite")
	command.SetGlobalVerbose(true)
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
func (e *e2e) SetupTest() {
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
	e.run("make", "image", "IMAGE="+testImage)
	e.logf("Loading container image into nodes")
	e.run(
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, testImage,
	)
}

// TearDownTest stops the kind cluster.
func (e *e2e) TearDownTest() {
	e.logf("Destroying cluster")
	e.run(
		e.kindPath, "delete", "cluster",
		"--name="+e.clusterName,
		"-v=3",
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

func (e *e2e) kubectlOperatorNS(args ...string) string {
	return e.kubectl(
		append([]string{"-n", config.OperatorName}, args...)...,
	)
}

func (e *e2e) logf(format string, a ...interface{}) {
	e.logger.Info(fmt.Sprintf(format, a...))
}

func (e *e2e) execNode(node string, args ...string) string {
	return e.run("docker", append([]string{"exec", node}, args...)...)
}
