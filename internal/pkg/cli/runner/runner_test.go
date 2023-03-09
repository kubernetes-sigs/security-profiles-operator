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

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/runner/runnerfakes"
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
