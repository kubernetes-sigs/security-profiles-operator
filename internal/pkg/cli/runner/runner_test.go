//go:build linux
// +build linux

/*
Copyright 2023 The Kubernetes Authors.

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
	"testing"
	"time"

	"github.com/nxadm/tail"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/runner/runnerfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
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
			name: "failure on YamlUnmarshal",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.YamlUnmarshalReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on JSONMarshal",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.JSONMarshalReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on JSONUnmarshal",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.JSONUnmarshalReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
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
			name: "failure on InitSeccomp",
			prepare: func(mock *runnerfakes.FakeImpl) {
				mock.InitSeccompReturns(0, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
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
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &runnerfakes.FakeImpl{}
			prepare(mock)

			sut := New(Default())
			sut.impl = mock

			err := sut.Run()
			assert(err)
		})
	}
}

func waitForFunctionCall(t *testing.T, fn func() int) {
	t.Helper()

	countGreaterZero := false
	for i := 0; i < 5; i++ {
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
		prepare func(*runnerfakes.FakeImpl, chan *tail.Line)
		assert  func(*runnerfakes.FakeImpl, chan *tail.Line)
	}{
		{
			name: "success with seccomp line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
				mock.IsAuditLineReturns(true)
				mock.ExtractAuditLineReturns(
					&types.AuditLine{
						AuditType: types.AuditTypeSeccomp,
						ProcessID: testPid,
					}, nil)
				mock.PidLoadReturns(testPid)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{}
				waitForFunctionCall(t, mock.PrintfCallCount)
				arg, _ := mock.PrintfArgsForCall(0)
				require.Contains(t, arg, "Seccomp")
			},
		},
		{
			name: "success with seccomp line but unidentified syscall number",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
				mock.IsAuditLineReturns(true)
				mock.ExtractAuditLineReturns(
					&types.AuditLine{
						AuditType: types.AuditTypeSeccomp,
						ProcessID: testPid,
					}, nil)
				mock.PidLoadReturns(testPid)
				mock.GetNameReturns("", errTest)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{}
				waitForFunctionCall(t, mock.GetNameCallCount)
				require.Zero(t, mock.PrintfCallCount())
			},
		},
		{
			name: "success with AppArmor line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
				mock.IsAuditLineReturns(true)
				mock.ExtractAuditLineReturns(
					&types.AuditLine{
						AuditType: types.AuditTypeApparmor,
						ProcessID: testPid,
					}, nil)
				mock.PidLoadReturns(testPid)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{}
				waitForFunctionCall(t, mock.PrintfCallCount)
				arg, _ := mock.PrintfArgsForCall(0)
				require.Contains(t, arg, "AppArmor")
			},
		},
		{
			name: "success with SELinux line",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
				mock.IsAuditLineReturns(true)
				mock.ExtractAuditLineReturns(
					&types.AuditLine{
						AuditType: types.AuditTypeSelinux,
						ProcessID: testPid,
					}, nil)
				mock.PidLoadReturns(testPid)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{}
				waitForFunctionCall(t, mock.PrintfCallCount)
				arg, _ := mock.PrintfArgsForCall(0)
				require.Contains(t, arg, "SELinux")
			},
		},
		{
			name: "failure on ExtractAuditLine",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
				mock.IsAuditLineReturns(true)
				mock.ExtractAuditLineReturns(nil, errTest)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{}
				require.Zero(t, mock.PidLoadCallCount())
			},
		},
		{
			name: "failure on IsAuditLine",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
				mock.IsAuditLineReturns(false)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{}
				require.Zero(t, mock.PidLoadCallCount())
			},
		},
		{
			name: "failure on Lines",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.LinesReturns(lineChan)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				lineChan <- &tail.Line{Err: errTest}
				require.Zero(t, mock.PidLoadCallCount())
			},
		},
		{
			name: "failure on TailFile",
			prepare: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.TailFileReturns(nil, errTest)
			},
			assert: func(mock *runnerfakes.FakeImpl, lineChan chan *tail.Line) {
				require.Zero(t, mock.LinesCallCount())
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &runnerfakes.FakeImpl{}
			lineChan := make(chan *tail.Line)
			prepare(mock, lineChan)

			sut := New(Default())
			sut.impl = mock

			go sut.startEnricher()
			assert(mock, lineChan)
		})
	}
}
