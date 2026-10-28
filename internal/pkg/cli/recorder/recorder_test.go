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

package recorder

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder/recorderfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
)

var errTest = errors.New("test")

type buffer struct {
	bytes.Buffer

	closeErr error
}

// Add a Close method to our buffer so that we satisfy io.WriteCloser.
func (b *buffer) Close() error {
	return b.closeErr
}

func TestRun(t *testing.T) {
	t.Parallel()

	defaultMock := func(mock *recorderfakes.FakeImpl) {
		mock.FindProcMountNamespaceReturns(1, nil)
		mock.IteratorNextReturnsOnCall(0, true)
		mock.IteratorKeyReturnsOnCall(0, []byte{1, 0, 0, 0, 0, 0, 0, 0})
		mock.SyscallsGetValueReturns([]byte{1}, nil)
		mock.BPFLSMEnabledReturns(true)
		mock.AppArmorProcessedReturns(bpfrecorder.BpfAppArmorProcessed{}, true)
	}

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *recorderfakes.FakeImpl) *Options
		assert  func(*testing.T, *recorderfakes.FakeImpl, error)
	}{
		{
			name: "success seccomp CRD",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.CommandRunReturns(1, nil)
				mock.IteratorNextReturnsOnCall(0, true)
				mock.IteratorKeyReturnsOnCall(0, []byte{1, 0, 0, 0, 0, 0, 0, 0})
				mock.SyscallsGetValueReturns([]byte{1}, nil)
				mock.FindProcMountNamespaceReturns(1, nil)
				defaultMock(mock)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
		{
			name: "success seccomp CRD with error on CmdWait",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CommandWaitReturns(errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
		{
			name: "success seccomp CRD with non matching mount namespace",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.FindProcMountNamespaceReturns(1, nil)
				mock.IteratorNextReturnsOnCall(0, true)
				mock.IteratorKeyReturnsOnCall(0, []byte{2, 0, 0, 0, 0, 0, 0, 0})
				mock.IteratorNextReturnsOnCall(1, true)
				mock.IteratorKeyReturnsOnCall(1, []byte{1, 0, 0, 0, 0, 0, 0, 0})

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
		{
			name: "success raw seccomp profile",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)

				options := Default()
				options.typ = TypeRawSeccomp

				return options
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 1, mock.CreateCallCount())
				require.Equal(t,
					strings.TrimSuffix(DefaultOutputFile, ".yaml")+".json",
					mock.CreateArgsForCall(0))
			},
		},
		{
			name: "failure seccomp CRD on Create",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CreateReturns(nil, errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on Close",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CreateReturns(&buffer{closeErr: errTest}, nil)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
				require.ErrorContains(t, err, "close file")
			},
		},
		{
			name: "failure creates no output file",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.SyscallsGetValueReturns(nil, errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
				require.Zero(t, mock.CreateCallCount())
			},
		},
		{
			name: "failure seccomp CRD on PrintObj",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.PrintObjReturns(errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure raw seccomp profile on WriteFile",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CreateReturns(nil, errTest)

				options := Default()
				options.typ = TypeRawSeccomp

				return options
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on SyscallsGetValue",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.SyscallsGetValueReturns(nil, errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "success seccomp skips syscall unknown to libseccomp",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.SyscallsGetValueReturns([]byte{1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "", errTest)
				mock.GetNameReturnsOnCall(1, "read", nil)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 2, mock.GetNameCallCount())
				require.Equal(t, 1, mock.PrintObjCallCount())

				obj, _ := mock.PrintObjArgsForCall(0)
				profile, ok := obj.(*seccompprofileapi.SeccompProfile)
				require.True(t, ok)
				require.Len(t, profile.Spec.Syscalls, 1)
				require.Contains(t, profile.Spec.Syscalls[0].Names, "read")
				require.NotContains(t, profile.Spec.Syscalls[0].Names, "")
			},
		},
		{
			name: "failure seccomp find mount namespace",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.FindProcMountNamespaceReturns(1, nil)
				mock.FindProcMountNamespaceReturns(1, nil)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "failure seccomp on FindProcMountNamespace",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.FindProcMountNamespaceReturns(0, errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
				require.Zero(t, mock.CommandRunCallCount(), "the command must not be left running")
			},
		},
		{
			// A further signal while the profile gets built ends spoc,
			// unless it is the same signal delivered twice.
			name: "success without starting the command",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.NotifyStub = func(c chan<- os.Signal, _ ...os.Signal) {
					c <- os.Interrupt
				}

				options := Default()
				options.noProcStart = true

				return options
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Zero(t, mock.CommandRunCallCount())
				require.Zero(t, mock.StopNotifyCallCount(), "a duplicate must not end spoc")
				require.Eventually(t, func() bool {
					return mock.StopNotifyCallCount() == 1
				}, 2*cli.DuplicateSignalWindow, 10*time.Millisecond)
			},
		},
		{
			// Without the command, every recorded mount namespace is
			// taken, of which there is none.
			name: "failure without starting the command if nothing got recorded",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.IteratorNextReturnsOnCall(0, false)
				mock.NotifyStub = func(c chan<- os.Signal, _ ...os.Signal) {
					c <- os.Interrupt
				}

				options := Default()
				options.noProcStart = true

				return options
			},
			assert: func(t *testing.T, _ *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errNothingRecorded)
			},
		},
		{
			name: "failure seccomp on CmdStart",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.CommandRunReturns(0, errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure seccomp on LoadBpfRecorder",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.LoadBpfRecorderReturns(errTest)

				return Default()
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "success all CRD",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				mock.CommandRunReturns(1, nil)
				defaultMock(mock)

				options := Default()
				options.typ = TypeAll

				return options
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 2, mock.PrintObjCallCount())
			},
		},
		{
			name: "no apparmor data",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.CommandRunReturns(1, nil)
				mock.AppArmorProcessedReturns(bpfrecorder.BpfAppArmorProcessed{}, false)

				options := Default()
				options.typ = TypeApparmor

				return options
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "find mntns 1 in apparmor data")
				require.Zero(t, mock.CreateCallCount())
			},
		},
		{
			name: "no BPF LSM",
			prepare: func(_ *testing.T, mock *recorderfakes.FakeImpl) *Options {
				defaultMock(mock)
				mock.BPFLSMEnabledReturns(false)

				options := Default()
				options.typ = TypeApparmor

				return options
			},
			assert: func(t *testing.T, mock *recorderfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrBPFLSMDisabled)
				require.ErrorContains(t, err, "lsm=")
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
			options := prepare(t, mock)

			sut := New(options)
			sut.impl = mock

			err := sut.Run()
			assert(t, mock, err)
		})
	}
}

func TestOutFile(t *testing.T) {
	t.Parallel()

	base := strings.TrimSuffix(DefaultOutputFile, ".yaml")

	for typ, want := range map[Type]string{
		TypeSeccomp:     DefaultOutputFile,
		TypeApparmor:    DefaultOutputFile,
		TypeAll:         DefaultOutputFile,
		TypeRawSeccomp:  base + ".json",
		TypeRawAppArmor: base + ".apparmor",
	} {
		options := Default()
		options.typ = typ

		require.Equal(t, want, New(options).outFile(), "type %s", typ)
	}

	options := Default()
	options.typ = TypeRawSeccomp
	options.outputFile = "/custom/file.yaml"
	options.outputFileSet = true

	require.Equal(t, "/custom/file.yaml", New(options).outFile())

	// The default file name, explicitly asked for, is kept as well.
	options.outputFile = DefaultOutputFile
	require.Equal(t, DefaultOutputFile, New(options).outFile())
}
