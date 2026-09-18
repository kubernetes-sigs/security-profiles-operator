//go:build linux && !no_bpf

/*
Copyright The Kubernetes Authors.

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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/release-utils/helpers"
	"sigs.k8s.io/yaml"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
)

var errRecorderStuck = errors.New("recorder did not exit on its own, killed it")

const (
	spocPath = "../../build/spoc"

	// spocLogTimeout bounds how long a test waits for a single expected line of
	// recorder output.
	spocLogTimeout = time.Minute

	// spocShutdownTimeout bounds how long a test waits for an interrupted
	// recorder to write out its profile and exit. Far above the second this
	// takes in practice, so a loaded CI machine does not trip it, and low
	// enough that the waits of a single test case still add up to less than
	// the timeout of the test binary itself.
	spocShutdownTimeout = 2 * time.Minute

	// pkillNoMatch is what pkill exits with when no process matched.
	pkillNoMatch = 1
)

//nolint:paralleltest // should not run in parallel
func TestSpoc(t *testing.T) {
	cmd := exec.Command("go", "build", "demobinary.go")
	err := cmd.Run()
	require.NoError(t, err, "failed to build demobinary.go")
	err = helpers.CopyFileLocal("demobinary", "demobinary-child", true)
	require.NoError(t, err)
	err = os.Chmod("demobinary-child", 0o700)
	require.NoError(t, err)

	t.Run("record", recordTest)
	t.Run("push-pull", pushPullTest)
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
			require.NotEmpty(t, profile.Filesystem.ReadOnlyPaths)
			require.Contains(t, profile.Filesystem.ReadOnlyPaths, readme)

			count := 0

			for _, s := range profile.Filesystem.ReadOnlyPaths {
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
			require.NotEmpty(t, profile.Filesystem.WriteOnlyPaths)
			require.Contains(t, profile.Filesystem.WriteOnlyPaths, "/dev/null")

			runWithProfile(t, profile, "./demobinary", "--file-write", "/dev/null")
		})
		t.Run("read-write", func(t *testing.T) {
			profile := recordAppArmor(t,
				"./demobinary",
				"--file-read", "/dev/null",
				"--file-write", "/dev/null",
			)
			require.NotNil(t, profile.Filesystem)
			require.NotEmpty(t, profile.Filesystem.ReadWritePaths)
			require.Contains(t, profile.Filesystem.ReadWritePaths, "/dev/null")

			runWithProfile(
				t,
				profile,
				"./demobinary",
				"--file-read",
				"/dev/null",
				"--file-write",
				"/dev/null",
			)
		})
		t.Run("create", func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "spoc-test-file")
			profile := recordAppArmor(t,
				"./demobinary",
				"--file-create", f,
			)

			require.NotNil(t, profile.Filesystem)
			require.NotEmpty(t, profile.Filesystem.WriteOnlyPaths)
			require.Contains(
				t,
				profile.Filesystem.WriteOnlyPaths,
				bpfrecorder.ReplaceVarianceInFilePath(f),
			)

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
			require.NotEmpty(t, profile.Filesystem.ReadWritePaths)
			require.Contains(
				t,
				profile.Filesystem.ReadWritePaths,
				bpfrecorder.ReplaceVarianceInFilePath(fileToRemove.Name()),
			)

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
		require.NotEmpty(t, profile.Filesystem.ReadOnlyPaths)
		require.NotEmpty(t, profile.Filesystem.ReadWritePaths)
		require.Contains(t, profile.Filesystem.ReadOnlyPaths, "/var/")
		require.Contains(t, profile.Filesystem.ReadOnlyPaths, "/usr/")
		require.Contains(
			t,
			profile.Filesystem.ReadWritePaths,
			bpfrecorder.ReplaceVarianceInFilePath(testDir1),
		)
		require.Contains(
			t,
			profile.Filesystem.ReadWritePaths,
			bpfrecorder.ReplaceVarianceInFilePath(testDir2),
		)

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
			require.NotEmpty(t, profile.Filesystem.ReadWritePaths)
			require.Contains(
				t,
				profile.Filesystem.ReadWritePaths,
				bpfrecorder.ReplaceVarianceInFilePath(sockPath),
			)

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
		profile := recordAppArmor(
			t,
			"./demobinary",
			"./demobinary-child",
			"--file-read",
			"/dev/null",
		)
		require.Contains(t, profile.Executable.AllowedExecutables[0], "/demobinary-child")
		require.Contains(t, profile.Filesystem.ReadOnlyPaths, "/dev/null")

		profile = recordAppArmor(t, "./demobinary", "./demobinary", "--file-read", "/dev/null")
		require.Contains(t, profile.Executable.AllowedExecutables[0], "/demobinary")
		require.Contains(t, profile.Filesystem.ReadOnlyPaths, "/dev/null")

		profile = recordAppArmor(
			t,
			"./demobinary",
			"./demobinary-child",
			"./demobinary-child",
			"--file-read",
			"/dev/null",
		)
		require.Contains(t, profile.Executable.AllowedExecutables[0], "/demobinary-child")
		require.Contains(t, profile.Filesystem.ReadOnlyPaths, "/dev/null")
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
		require.Contains(t, profile.Filesystem.ReadWritePaths, "/")
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
		require.NoError(t, err)

		spocLogs := scanLines(stderr)

		var stdout bytes.Buffer

		cmd.Stdout = &stdout

		// Start recorder and wait for it to set itself up.
		err = cmd.Start()
		require.NoError(t, err)

		// A test case that gives up early must not leave the recorder attached
		// for the ones after it. The flag keeps this off the happy path, which
		// reaps the recorder itself, kill included, and where a second Wait
		// would race the first one.
		reaped := false

		t.Cleanup(func() {
			if reaped {
				return
			}

			// Keep reading, silently because logging after the test case
			// completed panics: a recorder blocked writing into a pipe nobody
			// drains any more never gets to handle the signal below.
			go func() {
				for range spocLogs {
				}
			}()

			// Best effort: the recorder may also have died on its own, which is
			// what the test case is failing about.
			//nolint:errcheck // nothing left to report it to
			interruptRecorder(cmd.Process.Pid)
			//nolint:errcheck // same
			waitOrKill(cmd)
		})

		t.Log("waiting for SPOC to set up...")
		waitForLog(t, spocLogs, recorder.WaitForSigIntMessage)

		// Run binary...
		cmd2 := exec.Command(demobinary, "--net-tcp")
		err = cmd2.Run()
		require.NoError(t, err)

		t.Log("waiting for SPOC to register process exit...")
		waitForLog(t, spocLogs,
			fmt.Sprintf("Record pid exit (pid=%d)", cmd2.Process.Pid))

		// Wait until events are processed and stop the recorder...
		t.Log("sending SIGINT...")
		require.NoError(t, interruptRecorder(cmd.Process.Pid))

		// useful when binary crashed.
		drainLogs(t, spocLogs)

		reaped = true

		require.NoError(t, waitOrKill(cmd))

		require.Contains(t, stdout.String(), "allowTcp", "did not find TCP permission in profile")
	})
}

// interruptRecorder stops a running spoc recorder. We cannot simply use
// Process.Signal here as sudo will not forward SIGINT when running outside of a
// pty (i.e. in CI).
func interruptRecorder(pid int) error {
	//nolint:gosec // not a security risk
	if err := exec.Command(
		"sudo",
		"setsid",
		"kill",
		"-SIGINT",
		strconv.Itoa(pid),
	).Run(); err != nil {
		return fmt.Errorf("interrupt recorder: %w", err)
	}

	return nil
}

// killRecorder kills a spoc recorder that did not stop on its own. The kill
// targets the child of sudo rather than sudo itself, which runs as root and
// would just orphan the recorder.
func killRecorder(pid int) error {
	//nolint:gosec // not a security risk
	err := exec.Command(
		"sudo",
		"pkill",
		"-KILL",
		"-P",
		strconv.Itoa(pid),
	).Run()

	// Nothing to match means the recorder exited just after we gave up on it,
	// which is the outcome the kill was after anyway.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == pkillNoMatch {
		return nil
	}

	if err != nil {
		return fmt.Errorf("kill recorder: %w", err)
	}

	return nil
}

// waitOrKill reaps the recorder and kills it if it does not shut down. Waiting
// for it indefinitely would spend the whole test binary timeout on a single
// test case, which is what the SIGINT before it is meant to avoid.
func waitOrKill(cmd *exec.Cmd) error {
	done := make(chan error, 1)

	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("wait for recorder: %w", err)
		}

		return nil
	case <-time.After(spocShutdownTimeout):
	}

	killErr := killRecorder(cmd.Process.Pid)

	// Reap it either way: a kill that failed still leaves a Wait outstanding,
	// and nobody else is going to collect the process.
	select {
	case <-done:
	case <-time.After(spocShutdownTimeout):
	}

	if killErr != nil {
		return killErr
	}

	return errRecorderStuck
}

// scanLines pumps the recorder output into a channel. The reader lives in its
// own goroutine so that waitForLog can give up on a line that never arrives,
// and it never logs itself: a t.Log after the test completed panics.
func scanLines(r io.Reader) <-chan string {
	lines := make(chan string)

	go func() {
		defer close(lines)

		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	return lines
}

// waitForLog consumes the recorder output until it contains match. Waiting
// forever would burn the whole test binary timeout and take every other test
// case down with it, so a missing line fails this one instead.
func waitForLog(t *testing.T, lines <-chan string, match string) {
	t.Helper()

	timeout := time.After(spocLogTimeout)

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("spoc exited before logging %q", match)
			}

			t.Log(line)

			if strings.Contains(line, match) {
				return
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %q in the spoc output", match)
		}
	}
}

// drainLogs logs whatever the recorder has left to say, which is useful when it
// crashed. Bounded like waitForLog, because a recorder that never closes its
// output would otherwise block until the test binary times out.
func drainLogs(t *testing.T, lines <-chan string) {
	t.Helper()

	timeout := time.After(spocShutdownTimeout)

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return
			}

			t.Log(line)
		case <-timeout:
			t.Fatal("timed out waiting for the spoc output to end")
		}
	}
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

//
//nolint:unparam // `binary` arg for consistency with `record`/`recordAppArmor`.
func runWithProfile(
	t *testing.T,
	profile apparmorprofileapi.AppArmorAbstract,
	binary string,
	args ...string,
) {
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
