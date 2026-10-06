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
	"os"
	"os/exec"
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
		prepare func(*commandfakes.FakeImpl)
		assert  func(*commandfakes.FakeImpl, error, error)
	}{
		{
			name: "success",
			prepare: func(mock *commandfakes.FakeImpl) {
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.NoError(t, runErr)
				require.NoError(t, waitErr)
			},
		},
		{
			name: "failure on Wait",
			prepare: func(mock *commandfakes.FakeImpl) {
				mock.CmdWaitReturns(errTest)
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.NoError(t, runErr)
				require.Error(t, waitErr)
			},
		},
		{
			name: "success with error on Signal",
			prepare: func(mock *commandfakes.FakeImpl) {
				mock.NotifyCalls(func(c chan<- os.Signal, s ...os.Signal) { c <- s[0] })
				mock.SignalReturns(errTest)
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.NoError(t, runErr)
				require.NoError(t, waitErr)
			},
		},
		{
			name: "failure on CmdStart",
			prepare: func(mock *commandfakes.FakeImpl) {
				mock.CmdStartReturns(errTest)
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.Error(t, runErr)
				require.NoError(t, waitErr)
				require.Equal(t, 1, mock.StopCallCount())
			},
		},
		{
			name:    "signals are restored after Wait",
			prepare: func(mock *commandfakes.FakeImpl) {},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
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
			prepare(mock)

			sut := New(Default())
			sut.impl = mock

			_, runErr := sut.Run()
			waitErr := sut.Wait()

			assert(mock, runErr, waitErr)
		})
	}
}

func TestRunForwardsSignals(t *testing.T) {
	t.Parallel()

	mock := &commandfakes.FakeImpl{}

	var signals chan<- os.Signal

	mock.NotifyCalls(func(c chan<- os.Signal, _ ...os.Signal) { signals = c })

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
		signals <- sig

		select {
		case got := <-forwarded:
			require.Equal(t, sig, got)
		case <-time.After(10 * time.Second):
			require.FailNow(t, "signal not forwarded", "%v", sig)
		}
	}

	require.NoError(t, sut.Wait())
	require.Equal(t, 1, mock.StopCallCount())
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
			mock.CommandReturns(exec.Command("true"))
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

			err := exec.Command(tc.cmd[0], tc.cmd[1:]...).Run()
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
		privileged bool
		homeErr    error
		wantCred   bool
		wantErr    error
	}{
		{name: "dropped", sudoUID: "1000", wantCred: true},
		{name: "not in a sudo environment", sudoUID: ""},
		{name: "privileged", sudoUID: "1000", privileged: true},
		{name: "home directory lookup fails", sudoUID: "1000", homeErr: errTest, wantErr: errTest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_UID", tc.sudoUID)
			t.Setenv("SUDO_GID", "1001")
			t.Setenv("SUDO_USER", "user")
			t.Setenv("SUDO_COMMAND", "spoc")

			mock := &commandfakes.FakeImpl{}
			mock.CommandReturns(exec.Command("true"))
			mock.GetHomeDirectoryReturns("/home/user", tc.homeErr)

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
			require.Equal(t, &syscall.Credential{Uid: 1000, Gid: 1001}, cmd.SysProcAttr.Credential)
			require.Contains(t, cmd.Env, "HOME=/home/user")
			require.Contains(t, cmd.Env, "USER=user")

			for _, env := range cmd.Env {
				require.NotContains(t, env, "SUDO_")
			}
		})
	}
}
