// +build linux

/*
Copyright 2021 The Kubernetes Authors.

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

package bpfrecorder

import (
	"encoding/json"
	"io/ioutil"
	"syscall"
	"testing"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
)

const (
	node        = "test-node"
	validGoArch = "amd64"
)

var (
	errTest = errors.New("test")
	machine = []int8{'x', '8', '6', '_', '6', '4'}
	release = []int8{
		'3', '.', '1', '0', '.', '0', '-', '1', '0', '6', '2', '.', '1',
		'.', '1', '.', 'e', 'l', '7', '.', 'x', '8', '6', '_', '6', '4',
	}
)

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*bpfrecorderfakes.FakeImpl)
		assert  func(*bpfrecorderfakes.FakeImpl, error)
	}{
		{ // Success
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.Nil(t, err)
			},
		},
		{ // SetTTL fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.SetTTLReturns(errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // Getenv returns nothing
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns("")
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // InClusterConfig fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.InClusterConfigReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // NewForConfig fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.NewForConfigReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // Listen fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // ServeFails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ServeReturns(errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load wrong GOARCH
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns("invalid")
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:NewModuleFromBufferArgs fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:BPFLoadObject fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.BPFLoadObjectReturns(errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetProgram fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetProgramReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:AttachTracepoint fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.AttachTracepointReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetMap fails on first call
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetMapReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetMap fails on second call
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetMapReturnsOnCall(1, nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:InitRingBuf fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.InitRingBufReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:Unmarshal fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalReturns(errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:ReadOSRelease fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.ReadOSReleaseReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath succeeds
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{
					"ID": "centos", "VERSION_ID": "7",
				}, nil)
				mock.UnameCalls(func(res *syscall.Utsname) error {
					copy(res.Machine[:], machine)
					copy(res.Release[:], release)
					return nil
				})
				mock.TempFileCalls(ioutil.TempFile)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:Write fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{
					"ID": "centos", "VERSION_ID": "7",
				}, nil)
				mock.UnameCalls(func(res *syscall.Utsname) error {
					copy(res.Machine[:], machine)
					copy(res.Release[:], release)
					return nil
				})
				mock.WriteReturns(0, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:TempFile fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{
					"ID": "centos", "VERSION_ID": "7",
				}, nil)
				mock.UnameCalls(func(res *syscall.Utsname) error {
					copy(res.Machine[:], machine)
					copy(res.Release[:], release)
					return nil
				})
				mock.TempFileReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath kernel not found
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{
					"ID": "centos", "VERSION_ID": "7",
				}, nil)
				mock.UnameCalls(func(res *syscall.Utsname) error {
					copy(res.Machine[:], machine)
					return nil
				})
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath architecture not found
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{
					"ID": "centos", "VERSION_ID": "7",
				}, nil)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:Uname fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{
					"ID": "centos", "VERSION_ID": "7",
				}, nil)
				mock.UnameReturns(errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath OS version ID not found
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{"ID": "centos"}, nil)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath OS ID not found
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalCalls(json.Unmarshal)
				mock.ReadOSReleaseReturns(map[string]string{}, nil)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
	} {
		mock := &bpfrecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := New(logr.DiscardLogger{})
		sut.impl = mock

		err := sut.Run()
		tc.assert(mock, err)
	}
}
