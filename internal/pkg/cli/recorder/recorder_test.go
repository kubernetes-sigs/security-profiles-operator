//go:build linux && !no_bpf
// +build linux,!no_bpf

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

package recorder

import (
	"bytes"
	"errors"
	"testing"

	"github.com/containers/common/pkg/seccomp"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder/recorderfakes"
)

var errTest = errors.New("test")

type buffer struct {
	bytes.Buffer
}

// Add a Close method to our buffer so that we satisfy io.WriteCloser.
func (b *buffer) Close() error {
	return nil
}

func TestRun(t *testing.T) {
	t.Parallel()

	defaultMock := func(mock *recorderfakes.FakeImpl) {
		mock.FindProcMountNamespaceReturns(1, nil)
		mock.IteratorNextReturnsOnCall(0, true)
		mock.IteratorKeyReturnsOnCall(0, []byte{1, 0, 0, 0, 0, 0, 0, 0})
		mock.SyscallsGetValueReturns([]byte{1}, nil)
	}

	for _, tc := range []struct {
		name    string
		prepare func(*recorderfakes.FakeImpl) *Options
		assert  func(*recorderfakes.FakeImpl, error)
	}{
		{
			name: "success seccomp CRD",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.CommandRunReturns(1, nil)
				mock.IteratorNextReturnsOnCall(0, true)
				mock.IteratorKeyReturnsOnCall(0, []byte{1, 0, 0, 0, 0, 0, 0, 0})
				mock.SyscallsGetValueReturns([]byte{1}, nil)
				mock.FindProcMountNamespaceReturns(1, nil)
				defaultMock(mock)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
		{
			name: "success seccomp CRD with error on CmdWait",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CommandWaitReturns(errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
		{
			name: "success seccomp CRD with non matching mount namespace",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.FindProcMountNamespaceReturns(1, nil)
				mock.IteratorNextReturnsOnCall(0, true)
				mock.IteratorKeyReturnsOnCall(0, []byte{2, 0, 0, 0, 0, 0, 0, 0})
				mock.IteratorNextReturnsOnCall(1, true)
				mock.IteratorKeyReturnsOnCall(1, []byte{1, 0, 0, 0, 0, 0, 0, 0})
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
		{
			name: "success raw seccomp profile",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				options := Default()
				options.typ = TypeRawSeccomp
				return options
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, mock.CreateCallCount())
			},
		},
		{
			name: "failure seccomp CRD on Create",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CreateReturns(nil, errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp CRD on PrintObj",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.PrintObjReturns(errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure raw seccomp profile on WriteFile",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CreateReturns(nil, errTest)
				options := Default()
				options.typ = TypeRawSeccomp
				return options
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure raw seccomp profile on MarshalIndent",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.MarshalIndentReturns(nil, errTest)
				options := Default()
				options.typ = TypeRawSeccomp
				return options
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on GoArchToSeccompArch",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.GoArchToSeccompArchReturns(seccomp.Arch(""), errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on SyscallsGetValue",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.SyscallsGetValueReturns(nil, errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on GetName",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.GetNameReturns("", errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp find mount namespace",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.FindProcMountNamespaceReturns(1, nil)
				mock.FindProcMountNamespaceReturns(1, nil)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure seccomp on FindProcMountNamespace",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.FindProcMountNamespaceReturns(1, nil)
				mock.FindProcMountNamespaceReturns(0, errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on CmdStart",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.CommandRunReturns(0, errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on LoadBpfRecorder",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.LoadBpfRecorderReturns(errTest)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "success all CRD",
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.CommandRunReturns(1, nil)
				defaultMock(mock)
				options := Default()
				options.typ = TypeAll
				return options
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, 2, mock.PrintObjCallCount())
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &recorderfakes.FakeImpl{}
			buf := buffer{}
			mock.CreateReturns(&buf, nil)
			options := prepare(mock)

			sut := New(options)
			sut.impl = mock

			err := sut.Run()
			assert(mock, err)
		})
	}
}
