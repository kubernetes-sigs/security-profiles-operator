// +build e2e

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
	"github.com/kubernetes-sigs/seccomp-operator/internal/pkg/controllers/profile"
	"github.com/stretchr/testify/suite"
	"k8s.io/klog/klogr"
	"k8s.io/release/pkg/command"
	"k8s.io/release/pkg/util"
)

const (
	kindVersion = "v0.8.1"
	kindSHA512  = "ff71adddbe043df84c4dee82f034c6856bfc51c931bb7839d9c09d02fca93bfe961a9c05d7c657371963cc81febee175133598bba50fb1481a9faa06b42abdc3" // nolint: lll
	kindImage   = "kindest/node:v1.18.2"
	testImage   = "securityoperators/seccomp-operator:latest"
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
	e.clusterName = fmt.Sprintf("so-e2e-%d", time.Now().Unix())

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
		append([]string{"-n", profile.DefaultNamespace}, args...)...,
	)
}

func (e *e2e) logf(format string, a ...interface{}) {
	e.logger.Info(fmt.Sprintf(format, a...))
}

func (e *e2e) execNode(node string, args ...string) string {
	return e.run("docker", append([]string{"exec", node}, args...)...)
}
