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
	kindImage   = "kindest/node:v1.18.2"
	testImage   = "securityoperators/seccomp-operator:latest"
)

type e2e struct {
	suite.Suite
	kindPath    string
	clusterName string
}

func TestSuite(t *testing.T) {
	suite.Run(t, &e2e{})
}

// SetupSuite downloads kind
func (e *e2e) SetupSuite() {
	cwd, err := os.Getwd()
	e.Nil(err)

	parent_cwd := filepath.Dir(cwd)
	os.Chdir(parent_cwd)
	buildDir := filepath.Join(parent_cwd, "build")
	e.Nil(os.MkdirAll(buildDir, 0o755))

	e.kindPath = filepath.Join(buildDir, "kind")
	if !util.Exists(e.kindPath) {
		e.run(
			"curl", "-o", e.kindPath, "-fL",
			"https://github.com/kubernetes-sigs/kind/releases/download/"+
				kindVersion+"/kind-linux-amd64",
		)
		e.Nil(os.Chmod(e.kindPath, 0o755))
	}
}

// SetupTest starts a fresh kind cluster for each test
func (e *e2e) SetupTest() {
	// Deploy the cluster
	e.clusterName = fmt.Sprintf("so-e2e-%d", time.Now().Unix())

	cmd := exec.Command(
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

// TearDownTest stops the kind cluster
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

func (e *e2e) kubectl(args ...string) {
	e.run("kubectl", args...)
}
