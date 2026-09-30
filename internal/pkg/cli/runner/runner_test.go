//go:build linux

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

package runner

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/runner/runnerfakes"
)

var errTest = errors.New("test")

const seccompProfileYAML = "apiVersion: security-profiles-operator.x-k8s.io/v1\n" +
	"kind: SeccompProfile\nspec:\n  defaultAction: SCMP_ACT_ERRNO\n"

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		profile string
		prepare func(mock *runnerfakes.FakeImpl)
		assert  func(error)
	}{
		{
			name:    "success",
			prepare: func(mock *runnerfakes.FakeImpl) {},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "failure on ReadFile",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name:    "success with JSON profile",
			profile: "profile.json",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns([]byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), nil)
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "failure on invalid YAML profile",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns([]byte("{"), nil)
			},
			assert: func(err error) {
				require.ErrorContains(t, err, "unmarshal YAML profile")
			},
		},
		{
			name:    "failure on invalid JSON profile",
			profile: "profile.json",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns([]byte("{"), nil)
			},
			assert: func(err error) {
				require.ErrorContains(t, err, "unmarshal JSON profile")
			},
		},
		{
			name: "failure on SetupSeccomp",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.SetupSeccompReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on YAML profile of another kind",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns([]byte("apiVersion: security-profiles-operator.x-k8s.io/v1\n"+
					"kind: AppArmorProfile\n"), nil)
			},
			assert: func(err error) {
				require.ErrorContains(t, err, "expected a SeccompProfile, got AppArmorProfile")
			},
		},
		{
			name: "failure on YAML profile without kind",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns([]byte("spec:\n  defaultAction: SCMP_ACT_ERRNO\n"), nil)
			},
			assert: func(err error) {
				require.ErrorContains(t, err, "unmarshal YAML profile")
			},
		},
		{
			name: "failure on YAML profile with base profile",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.ReadFileReturns([]byte(seccompProfileYAML+"  baseProfileName: runc-v1.2.3\n"), nil)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, ErrBaseProfile)
				require.ErrorContains(t, err, "runc-v1.2.3")
			},
		},
		{
			name: "failure on CommandRun",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.CommandRunReturns(0, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on CommandWait",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.CommandWaitReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on CommandWait keeps the exit code",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.CommandWaitReturns(exec.Command("sh", "-c", "exit 42").Run())
			},
			assert: func(err error) {
				code, exited := command.ExitCode(err)
				require.True(t, exited)
				require.Equal(t, 42, code)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert
		profile := tc.profile

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &runnerfakes.FakeImpl{}
			mock.ReadFileReturns([]byte(seccompProfileYAML), nil)
			prepare(mock)

			options := Default()
			if profile != "" {
				options.profile = profile
			}

			sut := New(options)
			sut.impl = mock
			sut.enricherGracePeriod = 0

			err := sut.Run()
			assert(err)
		})
	}
}

func waitForFunctionCall(t *testing.T, fn func() int) {
	t.Helper()

	countGreaterZero := false

	for range 5 {
		if fn() > 0 {
			countGreaterZero = true

			break
		}

		time.Sleep(time.Second)
	}

	require.True(t, countGreaterZero)
}

func TestStartEnricher(t *testing.T) {
	const testPid = 123

	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*runnerfakes.FakeImpl, chan string)
		assert  func(*runnerfakes.FakeImpl, chan string)
	}{
		{
			name: "success with seccomp line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				lineChan <- seccompLine(testPid)

				waitForFunctionCall(t, mock.PrintfCallCount)

				arg, _ := mock.PrintfArgsForCall(0)
				require.Contains(t, arg, "Seccomp")
			},
		},
		{
			name: "success with seccomp line but unidentified syscall number",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
				mock.GetNameReturns("", errTest)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				lineChan <- seccompLine(testPid)

				waitForFunctionCall(t, mock.GetNameCallCount)
				require.Zero(t, mock.PrintfCallCount())
			},
		},
		{
			name: "success with AppArmor line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				lineChan <- fmt.Sprintf(
					`audit: type=1400 audit(1668191154.949:64): apparmor="DENIED" `+
						`operation="exec" profile="p" name="/bin/x" pid=%d comm="x"`, testPid,
				)

				waitForFunctionCall(t, mock.PrintfCallCount)
				arg, _ := mock.PrintfArgsForCall(0)
				require.Contains(t, arg, "AppArmor")
			},
		},
		{
			name: "success with SELinux line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				lineChan <- fmt.Sprintf(
					`type=AVC msg=audit(1613173578.156:2945): avc:  denied  { read } for  `+
						`pid=%d comm="x" scontext=system_u:system_r:container_t:s0 `+
						`tcontext=system_u:object_r:var_lib_t:s0 tclass=lnk_file permissive=0`, testPid,
				)

				waitForFunctionCall(t, mock.PrintfCallCount)
				arg, _ := mock.PrintfArgsForCall(0)
				require.Contains(t, arg, "SELinux")
			},
		},
		{
			name: "line of another process",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				lineChan <- seccompLine(testPid + 1)

				lineChan <- seccompLine(testPid)

				waitForFunctionCall(t, mock.PrintfCallCount)
				require.Equal(t, 1, mock.GetNameCallCount())
			},
		},
		{
			name: "no audit line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				lineChan <- "not an audit line"

				lineChan <- seccompLine(testPid)

				waitForFunctionCall(t, mock.PrintfCallCount)
				require.Equal(t, 1, mock.PrintfCallCount())
			},
		},
		{
			name: "failure while tailing",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.LinesReturns(lineChan)
				mock.TailErrReturns(errTest)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				close(lineChan)

				waitForFunctionCall(t, mock.TailErrCallCount)
				require.Zero(t, mock.PrintfCallCount())
			},
		},
		{
			name: "failure on TailFile",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				mock.TailFileReturns(nil, errTest)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan string) {
				require.Zero(t, mock.LinesCallCount())
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &runnerfakes.FakeImpl{}
			lineChan := make(chan string)
			prepare(mock, lineChan)

			sut := New(Default())
			sut.impl = mock
			sut.pid.Store(testPid)

			go sut.startEnricher()

			assert(mock, lineChan)
		})
	}
}

func seccompLine(pid int) string {
	return fmt.Sprintf(
		`type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 `+
			`pid=%d comm="ls" exe="/bin/ls" sig=0 arch=c000003e syscall=3 compat=0`, pid,
	)
}
