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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/release-utils/util"
	"sigs.k8s.io/yaml"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
)

const spocPath = "../../build/spoc"

//nolint:paralleltest // should not run in parallel
func TestSpoc(t *testing.T) {
	cmd := exec.Command("go", "build", "demobinary.go")
	err := cmd.Run()
	require.NoError(t, err, "failed to build demobinary.go")
	err = util.CopyFileLocal("demobinary", "demobinary-child", true)
	require.NoError(t, err)
	err = os.Chmod("demobinary-child", 0o700)
	require.NoError(t, err)

	t.Run("record", recordTest)
}

func recordTest(t *testing.T) {
	t.Run("AppArmor", recordAppArmorTest)
	t.Run("AppArmorUnsupported", recordAppArmorUnsupportedTest)
	t.Run("Seccomp", recordSeccompTest)
}

func recordAppArmorTest(t *testing.T) {
	if !bpfrecorder.BPFLSMEnabled() {
		t.Skip("BPF LSM disabled")
	}

	t.Run("file", func(t *testing.T) {
		t.Run("read", func(t *testing.T) {
			fileRead := fmt.Sprintf("../../README.md,/proc/1/limits,/proc/%d/limits", os.Getpid())
			profile := recordAppArmor(t,
				"./demobinary",
				"--file-read", fileRead,
			)
			readme, err := filepath.Abs("../../README.md")
			require.NoError(t, err)
			require.NotNil(t, profile.Filesystem)
			require.NotNil(t, profile.Filesystem.ReadOnlyPaths)
			require.Contains(t, *profile.Filesystem.ReadOnlyPaths, readme)

			count := 0

			for _, s := range *profile.Filesystem.ReadOnlyPaths {
				if s == "/proc/@{pid}/limits" {
					count++
				}
			}

			require.Equal(t, 1, count)

			runWithProfile(t, profile, "./demobinary", "--file-read", fileRead)
		})
		t.Run("write", func(t *testing.T) {
			profile := recordAppArmor(t,
				"./demobinary",
				"--file-write", "/dev/null",
			)
			require.NotNil(t, profile.Filesystem)
			require.NotNil(t, profile.Filesystem.WriteOnlyPaths)
			require.Contains(t, *profile.Filesystem.WriteOnlyPaths, "/dev/null")

			runWithProfile(t, profile, "./demobinary", "--file-write", "/dev/null")
		})
		t.Run("read-write", func(t *testing.T) {
			profile := recordAppArmor(t,
				"./demobinary",
				"--file-read", "/dev/null",
				"--file-write", "/dev/null",
			)
			require.NotNil(t, profile.Filesystem)
			require.NotNil(t, profile.Filesystem.ReadWritePaths)
			require.Contains(t, *profile.Filesystem.ReadWritePaths, "/dev/null")

			runWithProfile(t, profile, "./demobinary", "--file-read", "/dev/null", "--file-write", "/dev/null")
		})
		t.Run("create", func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "spoc-test-file")
			profile := recordAppArmor(t,
				"./demobinary",
				"--file-create", f,
			)

			require.NotNil(t, profile.Filesystem)
			require.NotNil(t, profile.Filesystem.WriteOnlyPaths)
			require.Contains(t, *profile.Filesystem.WriteOnlyPaths, bpfrecorder.ReplaceVarianceInFilePath(f))

			err := os.Remove(f)
			require.NoError(t, err)
			runWithProfile(t, profile, "./demobinary", "--file-create", f)
		})
		t.Run("remove", func(t *testing.T) {
			tempDir := t.TempDir()
			fileToRemove, err := os.CreateTemp(tempDir, "spoc-test")
			require.NoError(t, err)
			err = fileToRemove.Close()
			require.NoError(t, err)

			profile := recordAppArmor(t,
				"./demobinary",
				"--file-remove", fileToRemove.Name(),
			)
			require.NotNil(t, profile.Filesystem)
			require.NotNil(t, profile.Filesystem.ReadWritePaths)
			require.Contains(t, *profile.Filesystem.ReadWritePaths, bpfrecorder.ReplaceVarianceInFilePath(fileToRemove.Name()))

			fileToRemove2, err := os.CreateTemp(tempDir, "spoc-test")
			require.NoError(t, err)
			err = fileToRemove2.Close()
			require.NoError(t, err)

			runWithProfile(t, profile, "./demobinary", "--file-remove", fileToRemove2.Name())
			_, err = os.Stat(fileToRemove2.Name())
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	})
	t.Run("directories", func(t *testing.T) {
		tempDir := t.TempDir()
		testDir1 := filepath.Join(tempDir, "dir1") + "/"
		testDir2 := filepath.Join(tempDir, "dir2") + "/"
		dirs := fmt.Sprintf("%s,%s", strings.TrimRight(testDir1, "/"), testDir2)

		profile := recordAppArmor(t,
			"./demobinary",
			"--dir-read", "/var,/usr/",
			"--dir-create", dirs,
		)
		require.NotNil(t, profile.Filesystem)
		require.NotNil(t, profile.Filesystem.ReadOnlyPaths)
		require.NotNil(t, profile.Filesystem.ReadWritePaths)
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/var/")
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/usr/")
		require.Contains(t, *profile.Filesystem.ReadWritePaths, bpfrecorder.ReplaceVarianceInFilePath(testDir1))
		require.Contains(t, *profile.Filesystem.ReadWritePaths, bpfrecorder.ReplaceVarianceInFilePath(testDir2))

		runWithProfile(t, profile,
			"./demobinary",
			"--dir-read", "/var,/usr/",
			"--dir-remove", dirs,
		)
	})
	t.Run("socket", func(t *testing.T) {
		t.Run("unix", func(t *testing.T) {
			sockPath := filepath.Join(t.TempDir(), "test.sock")
			profile := recordAppArmor(t, "./demobinary", "--net-unix", sockPath)
			require.NotNil(t, profile.Filesystem)
			require.NotNil(t, profile.Filesystem.ReadWritePaths)
			require.Contains(t, *profile.Filesystem.ReadWritePaths, bpfrecorder.ReplaceVarianceInFilePath(sockPath))

			err := os.Remove(sockPath)
			require.NoError(t, err)
			runWithProfile(t, profile,
				"./demobinary", "--net-unix", sockPath,
			)
		})
		t.Run("tcp", func(t *testing.T) {
			profile := recordAppArmor(t, "./demobinary", "--net-tcp")
			require.True(t, *profile.Network.Protocols.AllowTCP)
			require.Nil(t, profile.Capability)
			runWithProfile(t, profile, "./demobinary", "--net-tcp")
		})
		t.Run("udp", func(t *testing.T) {
			profile := recordAppArmor(t, "./demobinary", "--net-udp")
			require.True(t, *profile.Network.Protocols.AllowUDP)
			require.Nil(t, profile.Capability)
			runWithProfile(t, profile, "./demobinary", "--net-udp")
		})
		t.Run("icmp", func(t *testing.T) {
			profile := recordAppArmor(t, "--privileged", "./demobinary", "--net-icmp")
			require.True(t, *profile.Network.AllowRaw)
			require.Contains(t, profile.Capability.AllowedCapabilities, "net_raw")
		})
	})
	t.Run("capabilities", func(t *testing.T) {
		profile := recordAppArmor(t, "--privileged", "./demobinary", "--cap-sys-admin")
		require.Contains(t, profile.Capability.AllowedCapabilities, "sys_admin")

		if os.Geteuid() != 0 {
			profile = recordAppArmor(t, "./demobinary", "--cap-sys-admin")
			require.NotContains(t, profile.Capability.AllowedCapabilities, "sys_admin")
		}
	})
	t.Run("subprocess", func(t *testing.T) {
		profile := recordAppArmor(t, "./demobinary", "./demobinary-child", "--file-read", "/dev/null")
		require.Contains(t, (*profile.Executable.AllowedExecutables)[0], "/demobinary-child")
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/dev/null")

		profile = recordAppArmor(t, "./demobinary", "./demobinary", "--file-read", "/dev/null")
		require.Contains(t, (*profile.Executable.AllowedExecutables)[0], "/demobinary")
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/dev/null")

		profile = recordAppArmor(t, "./demobinary", "./demobinary-child", "./demobinary-child", "--file-read", "/dev/null")
		require.Contains(t, (*profile.Executable.AllowedExecutables)[0], "/demobinary-child")
		require.Contains(t, *profile.Filesystem.ReadOnlyPaths, "/dev/null")
	})
	t.Run("huge pages", func(t *testing.T) {
		page, err := syscall.Mmap(-1, 0, 8192,
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_PRIVATE|syscall.MAP_ANON|syscall.MAP_HUGETLB)
		if err != nil {
			t.Skip("No huge page support.")
		} else {
			err = syscall.Munmap(page)
			require.NoError(t, err)
		}

		profile := recordAppArmor(t, "./demobinary", "--hugepage")
		require.Contains(t, *profile.Filesystem.ReadWritePaths, "/")
		runWithProfile(t, profile, "./demobinary", "--hugepage")
	})
	t.Run("no-proc-start", func(t *testing.T) {
		demobinary, err := filepath.Abs("./demobinary")
		require.NoError(t, err)

		cmd := exec.Command(
			"sudo",
			spocPath,
			"record",
			"--no-proc-start",
			"-t", "apparmor",
			"-o", "/dev/stdout",
			demobinary,
		)
		stderr, err := cmd.StderrPipe()
		spocLogs := bufio.NewScanner(stderr)

		require.NoError(t, err)

		var stdout bytes.Buffer
		cmd.Stdout = &stdout

		// Start recorder and wait for it to set itself up.
		err = cmd.Start()
		require.NoError(t, err)

		t.Log("waiting for SPOC to set up...")

		for spocLogs.Scan() {
			t.Log(spocLogs.Text())

			if strings.Contains(spocLogs.Text(), recorder.WaitForSigIntMessage) {
				break
			}
		}
		// Run binary...
		cmd2 := exec.Command(demobinary, "--net-tcp")
		err = cmd2.Run()
		require.NoError(t, err)

		t.Log("waiting for SPOC to register process exit...")

		for spocLogs.Scan() {
			t.Log(spocLogs.Text())

			if strings.Contains(spocLogs.Text(), fmt.Sprintf("record pid exit: %d.", cmd2.Process.Pid)) {
				break
			}
		}

		// Wait until events are processed and stop the recorder...
		t.Log("sending SIGINT...")
		// We cannot simply use cmd.Process.Signal here as sudo will not forward
		// SIGINT when running outside of a pty (i.e. in CI)
		//nolint:gosec // not a security risk
		err = exec.Command(
			"sudo",
			"setsid",
			"kill",
			"-SIGINT",
			strconv.Itoa(cmd.Process.Pid),
		).Run()
		require.NoError(t, err)

		// useful when binary crashed.
		for spocLogs.Scan() {
			t.Log(spocLogs.Text())
		}

		err = cmd.Wait()
		require.NoError(t, err)

		require.Contains(t, stdout.String(), "allowTcp", "did not find TCP permission in profile")
	})
}

func recordAppArmorUnsupportedTest(t *testing.T) {
	if bpfrecorder.BPFLSMEnabled() {
		t.Skip("BPF LSM enabled")
	}

	_, err := runSpoc(
		t,
		"record",
		"-t",
		"apparmor",
		"-o",
		"/dev/stdout",
		"./demobinary",
	)
	require.Error(t, err)
}

func recordSeccompTest(t *testing.T) {
	profile := recordSeccomp(t, "./demobinary", "--net-tcp")
	require.Contains(t, profile.Syscalls[0].Names, "listen")
}

func runSpoc(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()

	args = append([]string{spocPath}, args...)
	cmd := exec.Command(
		"sudo",
		args...,
	)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()

	return out, err
}

//nolint:unparam // `binary` arg for consistency with `record`/`recordAppArmor`.
func runWithProfile(t *testing.T, profile apparmorprofileapi.AppArmorAbstract, binary string, args ...string) {
	t.Helper()
	// Create profile file
	demobinary, err := filepath.Abs("./demobinary")
	require.NoError(t, err)

	prof := apparmorprofileapi.AppArmorProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AppArmorProfile",
			APIVersion: apparmorprofileapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: demobinary},
		Spec:       apparmorprofileapi.AppArmorProfileSpec{Abstract: profile},
	}
	f, err := os.CreateTemp(t.TempDir(), "profile")
	require.NoError(t, err)
	contents, err := yaml.Marshal(prof)
	require.NoError(t, err)
	_, err = f.Write(contents)
	require.NoError(t, err)

	fmt.Println(string(contents))

	// Install profile
	_, err = runSpoc(t, "install", f.Name(), demobinary)
	require.NoError(t, err)

	cmd := exec.Command(
		binary,
		args...,
	)
	cmd.Stderr = os.Stderr
	runErr := cmd.Run()

	// Cleanup
	_, err = runSpoc(t, "remove", f.Name(), demobinary)
	require.NoError(t, err)
	require.NoError(t, runErr, "failed to run with installed profile")
}

func record(t *testing.T, typ string, profile client.Object, args ...string) {
	t.Helper()

	args = append([]string{
		"record", "-t", typ, "-o", "/dev/stdout", "--no-base-syscalls",
	}, args...)
	content, err := runSpoc(t, args...)
	require.NoError(t, err, "failed to run spoc")
	err = yaml.Unmarshal(content, &profile)
	require.NoError(t, err, "failed to parse yaml")
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
