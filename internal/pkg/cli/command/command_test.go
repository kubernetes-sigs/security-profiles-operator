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

package command

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command/commandfakes"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *commandfakes.FakeImpl)
		assert  func(*testing.T, *commandfakes.FakeImpl, error, error)
	}{
		{
			name: "success",
			prepare: func(_ *testing.T, mock *commandfakes.FakeImpl) {
			},
			assert: func(t *testing.T, mock *commandfakes.FakeImpl, runErr, waitErr error) {
				t.Helper()

				require.NoError(t, runErr)
				require.NoError(t, waitErr)
			},
		},
		{
			name: "failure on Wait",
			prepare: func(_ *testing.T, mock *commandfakes.FakeImpl) {
				mock.CmdWaitReturns(errTest)
			},
			assert: func(t *testing.T, mock *commandfakes.FakeImpl, runErr, waitErr error) {
				t.Helper()

				require.NoError(t, runErr)
				require.Error(t, waitErr)
			},
		},
		{
			name: "success with error on Signal",
			prepare: func(_ *testing.T, mock *commandfakes.FakeImpl) {
				mock.NotifyCalls(func(c chan<- os.Signal, s ...os.Signal) { c <- s[0] })
				mock.SignalReturns(errTest)
			},
			assert: func(t *testing.T, mock *commandfakes.FakeImpl, runErr, waitErr error) {
				t.Helper()

				require.NoError(t, runErr)
				require.NoError(t, waitErr)
			},
		},
		{
			name: "failure on CmdStart",
			prepare: func(_ *testing.T, mock *commandfakes.FakeImpl) {
				mock.CmdStartReturns(errTest)
			},
			assert: func(t *testing.T, mock *commandfakes.FakeImpl, runErr, waitErr error) {
				t.Helper()

				require.Error(t, runErr)
				require.NoError(t, waitErr)
				require.Equal(t, 1, mock.StopCallCount())
			},
		},
		{
			name:    "signals are restored after Wait",
			prepare: func(_ *testing.T, mock *commandfakes.FakeImpl) {},
			assert: func(t *testing.T, mock *commandfakes.FakeImpl, runErr, waitErr error) {
				t.Helper()

				require.NoError(t, runErr)
				require.NoError(t, waitErr)
				require.Equal(t, 1, mock.NotifyCallCount())
				require.Equal(t, 1, mock.StopCallCount())

				_, signals := mock.NotifyArgsForCall(0)
				require.ElementsMatch(t,
					[]os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}, signals,
				)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &commandfakes.FakeImpl{}
			prepare(t, mock)

			sut := New(Default())
			sut.impl = mock

			_, runErr := sut.Run()
			waitErr := sut.Wait()

			assert(t, mock, runErr, waitErr)
		})
	}
}

// signalSender sends signals to the channel the fake subscribed, unless the
// default handling got restored already, which closes the channel.
type signalSender struct {
	mu      sync.Mutex
	signals chan<- os.Signal
	stopped bool
}

func newSignalSender(mock *commandfakes.FakeImpl) *signalSender {
	s := &signalSender{}

	mock.NotifyCalls(func(c chan<- os.Signal, _ ...os.Signal) { s.signals = c })
	mock.StopCalls(func(chan<- os.Signal) {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.stopped = true
	})

	return s
}

// send sends the signal and reports whether it got sent. The channel only
// gets closed after Stop, which waits for the send.
func (s *signalSender) send(sig os.Signal) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return false
	}

	s.signals <- sig

	return true
}

func TestRunForwardsSignals(t *testing.T) {
	t.Parallel()

	mock := &commandfakes.FakeImpl{}
	sender := newSignalSender(mock)

	forwarded := make(chan os.Signal, 3)

	mock.SignalCalls(func(_ *exec.Cmd, sig os.Signal) error {
		forwarded <- sig

		// A failed forward must not end the forwarding.
		return errTest
	})

	sut := New(Default())
	sut.impl = mock

	_, err := sut.Run()
	require.NoError(t, err)

	for _, sig := range []os.Signal{syscall.SIGTERM, os.Interrupt, syscall.SIGHUP} {
		require.True(t, sender.send(sig))

		select {
		case got := <-forwarded:
			require.Equal(t, sig, got)
		case <-time.After(10 * time.Second):
			require.FailNow(t, "signal not forwarded", "%v", sig)
		}
	}

	require.NoError(t, sut.Wait())

	// A duplicate of the last signal may still arrive after the command
	// exited, which is ignored. The default handling comes back afterwards.
	sender.send(os.Interrupt)

	require.Eventually(t, func() bool {
		return mock.StopCallCount() == 1
	}, 10*time.Second, 10*time.Millisecond)
	require.Empty(t, forwarded)
}

// TestWaitKeepsSignalsAfterSignalDeath verifies that a command which got
// killed by a signal from the process group, before spoc handled its own copy
// of it, does not leave spoc to the duplicate of a parent which forwards it.
func TestWaitKeepsSignalsAfterSignalDeath(t *testing.T) {
	t.Parallel()

	mock := &commandfakes.FakeImpl{}
	sender := newSignalSender(mock)

	killed := exec.CommandContext(t.Context(), "sh", "-c", "kill -INT $$").Run()
	require.True(t, killedBySignal(killed))
	mock.CmdWaitReturns(killed)

	sut := New(Default())
	sut.impl = mock

	_, err := sut.Run()
	require.NoError(t, err)
	require.Equal(t, killed, sut.Wait())

	// Restoring the default handling right away would let the duplicate
	// terminate spoc.
	require.True(t, sender.send(os.Interrupt), "the default handling got restored right away")

	require.Eventually(t, func() bool {
		return mock.StopCallCount() == 1
	}, 10*time.Second, 10*time.Millisecond)
	require.Zero(t, mock.SignalCallCount())
}

// TestRunForwardsRepeatedSignalOnce verifies that a signal which arrives
// twice at once, like one sent to the process group of spoc which a parent
// forwards as well, reaches the command once, while another signal still
// gets forwarded.
func TestRunForwardsRepeatedSignalOnce(t *testing.T) {
	t.Parallel()

	mock := &commandfakes.FakeImpl{}

	var signals chan<- os.Signal

	mock.NotifyCalls(func(c chan<- os.Signal, _ ...os.Signal) { signals = c })

	forwarded := make(chan os.Signal, 3)

	mock.SignalCalls(func(_ *exec.Cmd, sig os.Signal) error {
		forwarded <- sig

		return nil
	})

	sut := New(Default())
	sut.impl = mock

	_, err := sut.Run()
	require.NoError(t, err)

	// The signals are handled in order, so the SIGHUP comes last.
	signals <- syscall.SIGTERM

	signals <- syscall.SIGTERM

	signals <- syscall.SIGHUP

	for _, want := range []os.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		select {
		case got := <-forwarded:
			require.Equal(t, want, got)
		case <-time.After(10 * time.Second):
			require.FailNow(t, "signal not forwarded", "%v", want)
		}
	}

	require.NoError(t, sut.Wait())
	require.Equal(t, 2, mock.SignalCallCount())
}

// TestRunDoesNotForwardTerminalInterrupt verifies that a SIGINT is not
// forwarded while the command is in the foreground process group of the
// terminal, which sends it to the command as well, while the other signals
// still are. A command in a process group of its own gets it forwarded.
func TestRunDoesNotForwardTerminalInterrupt(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		group     int
		groupErr  error
		forwarded []os.Signal
	}{
		{name: "foreground", group: 100, forwarded: []os.Signal{syscall.SIGTERM}},
		{
			name:      "own process group",
			group:     200,
			forwarded: []os.Signal{os.Interrupt, syscall.SIGTERM},
		},
		{
			name:      "failed process group lookup",
			groupErr:  errTest,
			forwarded: []os.Signal{os.Interrupt, syscall.SIGTERM},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &commandfakes.FakeImpl{}
			mock.ForegroundProcessGroupReturns(100, nil)
			mock.ProcessGroupReturns(tc.group, tc.groupErr)
			mock.CmdPidReturns(42)

			var signals chan<- os.Signal

			mock.NotifyCalls(func(c chan<- os.Signal, _ ...os.Signal) { signals = c })

			forwarded := make(chan os.Signal, 2)

			mock.SignalCalls(func(_ *exec.Cmd, sig os.Signal) error {
				forwarded <- sig

				return nil
			})

			sut := New(Default())
			sut.impl = mock

			_, err := sut.Run()
			require.NoError(t, err)

			// The signals are handled in order, so the SIGTERM comes last.
			signals <- os.Interrupt

			signals <- syscall.SIGTERM

			for _, want := range tc.forwarded {
				select {
				case got := <-forwarded:
					require.Equal(t, want, got)
				case <-time.After(10 * time.Second):
					require.FailNow(t, "signal not forwarded", "%v", want)
				}
			}

			require.NoError(t, sut.Wait())
			require.Len(t, tc.forwarded, mock.SignalCallCount())
			require.Equal(t, 42, mock.ProcessGroupArgsForCall(0))
		})
	}
}

// TestProcessGroup verifies the process group lookup of a command which runs
// in a process group of its own.
func TestProcessGroup(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		require.NoError(t, cmd.Process.Kill())
		require.Error(t, cmd.Wait(), "killed")
	})

	group, err := (&defaultImpl{}).ProcessGroup(cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, cmd.Process.Pid, group)

	own, err := (&defaultImpl{}).ProcessGroup(os.Getpid())
	require.NoError(t, err)
	require.NotEqual(t, group, own)
}

func TestRunPreStart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		preErr    error
		startErr  error
		expectErr bool
		started   int
		postCalls int
	}{
		{name: "success", started: 1, postCalls: 1},
		{name: "failure on start", startErr: errTest, expectErr: true, started: 1, postCalls: 1},
		{name: "failure on PreStart", preErr: errTest, expectErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &commandfakes.FakeImpl{}
			mock.CommandReturns(exec.CommandContext(t.Context(), "true"))
			mock.CmdStartReturns(tc.startErr)

			postCalls := 0
			options := Default()
			options.PreStart = func(cmd *exec.Cmd) (func(), error) {
				cmd.Path = "/changed"

				return func() { postCalls++ }, tc.preErr
			}

			sut := New(options)
			sut.impl = mock

			_, err := sut.Run()
			if tc.expectErr {
				require.ErrorIs(t, err, errTest)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.started, mock.CmdStartCallCount())
			require.Equal(t, tc.postCalls, postCalls)

			if tc.started > 0 {
				require.Equal(t, "/changed", mock.CmdStartArgsForCall(0).Path)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		cmd    []string
		code   int
		exited bool
	}{
		{name: "success", cmd: []string{"true"}},
		{name: "exit status", cmd: []string{"sh", "-c", "exit 3"}, code: 3, exited: true},
		{name: "killed by signal", cmd: []string{"sh", "-c", "kill -TERM $$"}, code: 143, exited: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := exec.CommandContext(t.Context(), tc.cmd[0], tc.cmd[1:]...).Run()
			if !tc.exited {
				require.NoError(t, err)
			}

			code, exited := ExitCode(err)
			require.Equal(t, tc.exited, exited)
			require.Equal(t, tc.code, code)
		})
	}

	_, exited := ExitCode(errTest)
	require.False(t, exited)
}

// TestRunDropsSudoPrivileges verifies that the command runs as the user who
// invoked sudo, and that it does not run as root if that fails.
func TestRunDropsSudoPrivileges(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sudoUID    string
		euid       int
		privileged bool
		homeErr    error
		groupsErr  error
		wantCred   bool
		wantErr    error
	}{
		{name: "dropped", sudoUID: "1000", wantCred: true},
		{name: "not in a sudo environment", sudoUID: ""},
		// Like with sudo -u or an inherited sudo environment, only root can
		// switch to the invoking user.
		{name: "not root", sudoUID: "1000", euid: 1002},
		{name: "privileged", sudoUID: "1000", privileged: true},
		{name: "home directory lookup fails", sudoUID: "1000", homeErr: errTest, wantErr: errTest},
		{name: "group lookup fails", sudoUID: "1000", groupsErr: errTest, wantCred: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_UID", tc.sudoUID)
			t.Setenv("SUDO_GID", "1001")
			t.Setenv("SUDO_USER", "user")
			t.Setenv("SUDO_COMMAND", "spoc")

			mock := &commandfakes.FakeImpl{}
			mock.CommandReturns(exec.CommandContext(t.Context(), "true"))
			mock.GetHomeDirectoryReturns("/home/user", tc.homeErr)
			mock.GetGroupIDsReturns([]uint32{1001, 27}, tc.groupsErr)
			mock.GeteuidReturns(tc.euid)

			options := Default()
			options.DropSudoPrivileges = !tc.privileged

			sut := New(options)
			sut.impl = mock

			_, err := sut.Run()
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorContains(t, err, "--"+FlagPrivileged)
				require.Zero(t, mock.CmdStartCallCount(), "the command must not run as root")

				return
			}

			require.NoError(t, err)
			require.NoError(t, sut.Wait())
			require.Equal(t, 1, mock.CmdStartCallCount())

			cmd := mock.CmdStartArgsForCall(0)
			if !tc.wantCred {
				require.True(t, cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil)

				return
			}

			require.Equal(t, 1, mock.GetHomeDirectoryCallCount())
			require.Equal(t, uint32(1000), mock.GetHomeDirectoryArgsForCall(0))
			require.Equal(t, uint32(1000), mock.GetGroupIDsArgsForCall(0))

			wantGroups := []uint32{1001, 27}
			if tc.groupsErr != nil {
				// Like before the groups were kept, the command runs
				// without supplementary groups.
				wantGroups = nil
			}

			require.Equal(
				t,
				&syscall.Credential{Uid: 1000, Gid: 1001, Groups: wantGroups},
				cmd.SysProcAttr.Credential,
			)
			require.Contains(t, cmd.Env, "HOME=/home/user")
			require.Contains(t, cmd.Env, "USER=user")
			require.Contains(t, cmd.Env, "LOGNAME=user")

			for _, env := range cmd.Env {
				require.NotContains(t, env, "SUDO_")
			}
		})
	}
}

// The home directory of a known user comes from the user database, without
// running sudo.
func TestGetHomeDirectoryOfKnownUser(t *testing.T) {
	t.Parallel()

	current, err := user.Current()
	require.NoError(t, err)

	uid, err := strconv.ParseUint(current.Uid, 10, 32)
	require.NoError(t, err)

	home, err := getHomeDirectory(uint32(uid))
	require.NoError(t, err)
	require.Equal(t, current.HomeDir, home)
}

func TestPasswdHomeDirectory(t *testing.T) {
	t.Parallel()

	home, err := passwdHomeDirectory("user:x:1000:1000:User:/home/user:/bin/bash\n")
	require.NoError(t, err)
	require.Equal(t, "/home/user", home)

	for _, entry := range []string{"", "user:x:1000", "user:x:1000:1000:User::/bin/bash"} {
		_, err := passwdHomeDirectory(entry)
		require.Error(t, err, entry)
	}
}

// TestCreateFile verifies that a file gets handed to the user who invoked
// spoc through sudo only if spoc runs as root and the file is in a directory
// of that user, and that no symlink or hard link gets written through then.
func TestCreateFile(t *testing.T) {
	owner := strconv.Itoa(os.Getuid())
	group := strconv.Itoa(os.Getgid())

	for _, tc := range []struct {
		name    string
		euid    int
		sudoUID string
		path    func(t *testing.T) string
		prepare func(t *testing.T, name string) (target string)
		chowned bool
		wantErr error
		errMsg  string
	}{
		{name: "new file in a directory of the sudo user", sudoUID: owner, chowned: true},
		{
			name:    "existing file in a directory of the sudo user",
			sudoUID: owner,
			prepare: func(t *testing.T, name string) string {
				t.Helper()
				require.NoError(t, os.WriteFile(name, []byte("old content"), 0o600))

				return ""
			},
			chowned: true,
		},
		{
			name:    "symlink in a directory of the sudo user",
			sudoUID: owner,
			prepare: func(t *testing.T, name string) string {
				t.Helper()

				target := filepath.Join(t.TempDir(), "passwd")
				require.NoError(t, os.WriteFile(target, []byte("old content"), 0o600))
				require.NoError(t, os.Symlink(target, name))

				return target
			},
			wantErr: syscall.ELOOP,
			errMsg:  "refusing to write through the symlink",
		},
		{
			name:    "hard link in a directory of the sudo user",
			sudoUID: owner,
			prepare: func(t *testing.T, name string) string {
				t.Helper()

				target := filepath.Join(filepath.Dir(name), "passwd")
				require.NoError(t, os.WriteFile(target, []byte("old content"), 0o600))
				require.NoError(t, os.Link(target, name))

				return target
			},
			wantErr: ErrNotSingleRegularFile,
		},
		{
			name:    "directory reached through a symlink",
			sudoUID: owner,
			path: func(t *testing.T) string {
				t.Helper()

				link := filepath.Join(t.TempDir(), "link")
				require.NoError(t, os.Symlink(t.TempDir(), link))

				return filepath.Join(link, "profile.yaml")
			},
			chowned: true,
		},
		{name: "directory of another user", sudoUID: owner + "1"},
		{name: "not in a sudo environment"},
		{name: "not root", euid: 1000, sudoUID: owner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_UID", tc.sudoUID)
			t.Setenv("SUDO_GID", group)

			name := filepath.Join(t.TempDir(), "profile.yaml")
			if tc.path != nil {
				name = tc.path(t)
			}

			target := ""
			if tc.prepare != nil {
				target = tc.prepare(t, name)
			}

			calls := 0
			chown := func(file *os.File, uid, gid int) error {
				calls++

				require.Equal(t, name, file.Name())
				require.Equal(t, os.Getuid(), uid)
				require.Equal(t, os.Getgid(), gid)

				return nil
			}

			file, err := createFile(name, 0o644, tc.euid, chown)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorContains(t, err, tc.errMsg)
				require.Zero(t, calls)

				content, err := os.ReadFile(target)
				require.NoError(t, err)
				require.Equal(t, "old content", string(content), "written through")

				return
			}

			require.NoError(t, err)

			_, err = file.WriteString("profile")
			require.NoError(t, err)
			require.NoError(t, file.Close())

			content, err := os.ReadFile(name)
			require.NoError(t, err)
			require.Equal(t, "profile", string(content))

			if tc.chowned {
				require.Equal(t, 1, calls)
			} else {
				require.Zero(t, calls)
			}
		})
	}
}

// TestHandOverIDsOutOfRange verifies that IDs which do not fit the int of a
// 32-bit platform keep the file owned by root instead of overflowing.
func TestHandOverIDsOutOfRange(t *testing.T) {
	t.Parallel()

	for _, ids := range [][2]uint32{{1 << 31, 0}, {0, 1 << 31}, {math.MaxUint32, math.MaxUint32}} {
		file, err := os.Create(filepath.Join(t.TempDir(), "profile.yaml"))
		require.NoError(t, err)

		chown := func(*os.File, int, int) error {
			t.Fatal("chown called")

			return nil
		}

		require.NoError(t, handOver(file, ids[0], ids[1], chown))
		require.NoError(t, file.Close())
	}
}

// TestCreateFileDirectory verifies that the name of a directory fails like
// before, instead of naming a file in the directory.
func TestCreateFileDirectory(t *testing.T) {
	chown := func(*os.File, int, int) error { return nil }

	for name, isDir := range map[string]bool{"profiles": true, "profiles/": true, "missing/": false} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
			t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))

			dir := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(dir, "profiles"), 0o700))

			path := dir + "/" + name

			// A missing directory fails with ENOENT instead of EISDIR on macOS.
			_, err := createFile(path, 0o644, 0, chown)
			require.Error(t, err)

			if isDir {
				require.ErrorIs(t, err, syscall.EISDIR)
				require.ErrorContains(t, err, "is a directory")
			}

			entries, err := os.ReadDir(filepath.Join(dir, "profiles"))
			require.NoError(t, err)
			require.Empty(t, entries)
			require.NoFileExists(t, filepath.Join(dir, "missing"))
		})
	}
}
