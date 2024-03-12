//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2024 The Kubernetes Authors.

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

package main_test

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/release-utils/util"
	"sigs.k8s.io/yaml"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
)

const spocPath = "../../build/spoc"

//nolint:paralleltest // should not run in parallel
func TestSpoc(t *testing.T) {
	cmd := exec.Command("go", "build", "demobinary.go")
	err := cmd.Run()
	require.Nil(t, err, "failed to build demobinary.go")
	err = util.CopyFileLocal("demobinary", "demobinary-child", true)
	require.Nil(t, err)
	err = os.Chmod("demobinary-child", 0o700)
	require.Nil(t, err)

	t.Run("record", recordTest)
}

func recordTest(t *testing.T) {
	t.Run("AppArmor", recordAppArmorTest)
	t.Run("Seccomp", recordSeccompTest)
}

func recordAppArmorTest(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		profile := recordAppArmor(t, "--file-read", "../../README.md", "--file-write", "/dev/null")
		// TODO: This is still wrong - it should be an absolute path.
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "../../README.md")
		require.Contains(t, *profile.Filesystem.WriteOnlyPaths, "/dev/null")

		profile = recordAppArmor(t, "--file-read", "/dev/null", "--file-write", "/dev/null")
		require.Contains(t, *profile.Filesystem.ReadWritePaths, "/dev/null")
	})
	t.Run("sockets", func(t *testing.T) {
		profile := recordAppArmor(t, "--net-tcp")
		require.True(t, *profile.Network.Protocols.AllowTCP)
		profile = recordAppArmor(t, "--net-udp")
		require.True(t, *profile.Network.Protocols.AllowUDP)
		profile = recordAppArmor(t, "--net-icmp")
		require.True(t, *profile.Network.AllowRaw)
	})

	t.Run("subprocess", func(t *testing.T) {
		profile := recordAppArmor(t, "./demobinary-child", "--file-read", "/dev/null")
		require.Contains(t, (*profile.Executable.AllowedExecutables)[0], "/demobinary-child")
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/dev/null")

		profile = recordAppArmor(t, "./demobinary", "--file-read", "/dev/null")
		require.Contains(t, (*profile.Executable.AllowedExecutables)[0], "/demobinary")
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/dev/null")
	})

	t.Run("no-start", func(t *testing.T) {
		demobinary, err := filepath.Abs("./demobinary")
		require.Nil(t, err)

		cmd := exec.Command(
			"sudo", spocPath,
			"record",
			"--no-start",
			"-t", "apparmor",
			"-o", "/dev/stdout",
			demobinary,
		)
		stderr, err := cmd.StderrPipe()
		spocLogs := bufio.NewScanner(stderr)
		require.Nil(t, err)
		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		// Start recorder and wait for it to set itself up.
		err = cmd.Start()
		require.Nil(t, err)

		t.Log("waiting for SPOC to set up...")
		for spocLogs.Scan() {
			if strings.Contains(spocLogs.Text(), recorder.WaitForSigIntMessage) {
				break
			}
		}

		// Run binary...
		cmd2 := exec.Command(demobinary, "--file-read", "/dev/null")
		err = cmd2.Run()
		require.Nil(t, err)

		t.Log("waiting for SPOC to receive an event...")
		for spocLogs.Scan() {
			if strings.Contains(spocLogs.Text(), "Received event:") {
				break
			}
		}

		// Wait until events are processed and stop the recorder...
		err = cmd.Process.Signal(os.Interrupt)
		require.Nil(t, err)
		err = cmd.Wait()
		require.Nil(t, err)

		require.Contains(t, stdout.String(), "/dev/null", "did not find file read in profile")
	})
}

func recordSeccompTest(t *testing.T) {
	profile := recordSeccomp(t, "--net-tcp")
	require.Contains(t, profile.Syscalls[0].Names, "listen")
}

func runSpoc(t *testing.T, args ...string) []byte {
	t.Helper()
	args = append([]string{spocPath}, args...)
	cmd := exec.Command("sudo", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	require.Nil(t, err, "failed to run spoc")
	return out
}

func record(t *testing.T, typ string, profile client.Object, args ...string) {
	t.Helper()
	args = append([]string{
		"record", "-t", typ, "-o", "/dev/stdout", "--no-base-syscalls", "./demobinary",
	}, args...)
	content := runSpoc(t, args...)
	err := yaml.Unmarshal(content, &profile)
	require.Nil(t, err, "failed to parse yaml")
}

func recordAppArmor(t *testing.T, args ...string) apparmorprofileapi.AppArmorAbstract {
	t.Helper()
	profile := apparmorprofileapi.AppArmorProfile{}
	record(t, "apparmor", &profile, args...)
	return profile.Spec.Abstract
}

func recordSeccomp(t *testing.T, args ...string) seccompprofileapi.SeccompProfileSpec {
	t.Helper()
	profile := seccompprofileapi.SeccompProfile{}
	record(t, "seccomp", &profile, args...)
	return profile.Spec
}
