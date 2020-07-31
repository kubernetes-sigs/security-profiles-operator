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

	"github.com/stretchr/testify/suite"
	"k8s.io/release/pkg/command"
	"k8s.io/release/pkg/util"
)

const (
	kindVersion = "v0.8.1"
	kindSHA512  = "ff71adddbe043df84c4dee82f034c6856bfc51c931bb7839d9c09d02fca93bfe961a9c05d7c657371963cc81febee175133598bba50fb1481a9faa06b42abdc3" // nolint: lll
	kindImage   = "kindest/node:v1.18.2"

	testImage = "securityoperators/seccomp-operator:latest"
)

type e2e struct {
	suite.Suite
	kindPath    string
	kubectlPath string
	clusterName string
}

func TestSuite(t *testing.T) {
	suite.Run(t, &e2e{})
}

// SetupSuite downloads kind and searches for kubectl in $PATH.
func (e *e2e) SetupSuite() {
	cwd, err := os.Getwd()
	e.Nil(err)

	parentCwd := filepath.Dir(cwd)
	e.Nil(os.Chdir(parentCwd))
	buildDir := filepath.Join(parentCwd, "build")
	e.Nil(os.MkdirAll(buildDir, 0o755))

	e.kindPath = filepath.Join(buildDir, "kind")
	if !util.Exists(e.kindPath) {
		e.run(
			"curl", "-o", e.kindPath, "-fL",
			"https://github.com/kubernetes-sigs/kind/releases/download/"+
				kindVersion+"/kind-linux-amd64",
		)
		e.Nil(os.Chmod(e.kindPath, 0o700))
		e.verifySHA256(e.kindPath, kindSHA512)
	}

	e.kubectlPath, err = exec.LookPath("kubectl")
	e.Nil(err)
}

// SetupTest starts a fresh kind cluster for each test.
func (e *e2e) SetupTest() {
	// Deploy the cluster
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
	e.kubectl("wait", "--for", "condition=ready", "nodes", "--all")

	// Build and load the test image
	e.run("make", "image", "IMAGE="+testImage)
	e.run(
		e.kindPath, "load", "docker-image", "--name="+e.clusterName, testImage,
	)
}

// TearDownTest stops the kind cluster.
func (e *e2e) TearDownTest() {
	e.run(
		e.kindPath, "delete", "cluster",
		"--name="+e.clusterName,
		"-v=3",
	)
}

func (e *e2e) run(cmd string, args ...string) {
	e.Nil(command.Execute(cmd, args...))
}

func (e *e2e) verifySHA256(binaryPath, sha256 string) {
	e.Nil(command.New("sha512sum", binaryPath).
		Pipe("grep", sha256).
		RunSilentSuccess(),
	)
}

func (e *e2e) kubectl(args ...string) {
	e.run(e.kubectlPath, args...)
}
