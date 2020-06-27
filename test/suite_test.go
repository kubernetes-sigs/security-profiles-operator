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

	buildDir := filepath.Join(filepath.Dir(cwd), "build")
	e.Nil(os.MkdirAll(buildDir, 0o755))

	e.kindPath = filepath.Join(buildDir, "kind")
	if !util.Exists(e.kindPath) {
		e.Nil(command.New(
			"curl", "-o", e.kindPath, "-fL",
			"https://github.com/kubernetes-sigs/kind/releases/download/"+
				kindVersion+"/kind-linux-amd64",
		).RunSuccess())
		e.Nil(os.Chmod(e.kindPath, 0o755))
	}
}

// SetupTest starts a fresh kind cluster for each test
func (e *e2e) SetupTest() {
	e.clusterName = fmt.Sprintf("so-e2e-%d", time.Now().Unix())

	cmd := exec.Command(
		e.kindPath, "create", "cluster",
		"--name="+e.clusterName,
		"--image="+kindImage,
		"--wait=1m",
		"-v=3",
		"--config=kind-config.yaml",
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	e.Nil(cmd.Run())
}

// TearDownTest stops the kind cluster
func (e *e2e) TearDownTest() {
	e.Nil(command.New(
		e.kindPath, "delete", "cluster",
		"--name="+e.clusterName,
		"-v=3",
	).RunSuccess())
}

func (e *e2e) Test1() {
	e.Nil(command.New("kubectl", "get", "nodes").RunSuccess())
}

func (e *e2e) Test2() {
	e.Nil(command.New("kubectl", "get", "nodes").RunSuccess())
}
