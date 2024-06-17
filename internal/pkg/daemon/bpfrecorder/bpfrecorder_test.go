//go:build linux && !no_bpf
// +build linux,!no_bpf

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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	node        = "test-node"
	validGoArch = "amd64"
	profile     = "profile"
	namespace   = "test-namespace"
	pod         = "test-pod"
	crioPrefix  = "cri-o://"
	containerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
)

var (
	errTest = errors.New("test")
	machine = []int8{'x', '8', '6', '_', '6', '4'}
	release = []int8{
		'3', '.', '1', '0', '.', '0', '-', '1', '0', '6', '2', '.', '1',
		'.', '1', '.', 'e', 'l', '7', '.', 'x', '8', '6', '_', '6', '4',
	}

	mntns uint32 = 1337
)

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*bpfrecorderfakes.FakeImpl)
		assert  func(error)
	}{
		{ // Success
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.DialMetricsReturns(&grpc.ClientConn{}, func() {}, nil)
			},
			assert: func(err error) {
				require.Nil(t, err)
			},
		},
		{ // Getenv returns nothing
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns("")
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // InClusterConfig fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.InClusterConfigReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // NewForConfig fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.NewForConfigReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // RemoveAll fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.RemoveAllReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // Listen fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // Chown fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ChownReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // connectMetrics:DialMetrics fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.DialMetricsReturns(nil, nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // connectMetrics:BpfIncClient fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.DialMetricsReturns(&grpc.ClientConn{}, func() {}, nil)
				mock.CloseGRPCReturns(errTest)
				mock.BpfIncClientReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // Readlink fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ReadlinkReturns("", errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // Atoi fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ParseUintReturns(0, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // ServeFails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ServeReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load wrong GOARCH
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns("invalid")
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:NewModuleFromBufferArgs fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:InitGlobalVariable fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.InitGlobalVariableReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:BPFLoadObject fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.BPFLoadObjectReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetProgram fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetProgramReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:AttachGeneric fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.AttachGenericReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetMap fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetMapReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},

		{ // load:InitRingBuf fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.InitRingBufReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:Unmarshal fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.UnmarshalReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:findBtfPath:ReadOSRelease fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.StatReturns(nil, errTest)
				mock.ReadOSReleaseReturns(nil, errTest)
			},
			assert: func(err error) {
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
				mock.TempFileCalls(os.CreateTemp)
			},
			assert: func(err error) {
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
			assert: func(err error) {
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
			assert: func(err error) {
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
			assert: func(err error) {
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
			assert: func(err error) {
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
			assert: func(err error) {
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
			assert: func(err error) {
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
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
	} {
		mock := &bpfrecorderfakes.FakeImpl{}
		tc.prepare(mock)
		sut := New("test", logr.Discard(), true, false)
		sut.impl = mock

		err := sut.Run()
		tc.assert(err)
	}
}

func TestStart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*bpfrecorderfakes.FakeImpl)
		assert  func(*BpfRecorder, error)
	}{
		{ // Success
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Nil(t, err)
				require.EqualValues(t, 1, sut.startRequests)
			},
		},
		{ // Success already running
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Nil(t, err)
				require.EqualValues(t, 1, sut.startRequests)
				_, err = sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				require.EqualValues(t, 2, sut.startRequests)
			},
		},
		{ // load failed wrong GOARCH
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns("invalid")
			},
			assert: func(sut *BpfRecorder, err error) {
				require.NotNil(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
	} {
		mock := &bpfrecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := New("", logr.Discard(), true, false)
		sut.impl = mock

		_, err := sut.Start(context.Background(), &api.EmptyRequest{})
		tc.assert(sut, err)
	}
}

func TestStop(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*BpfRecorder, error)
	}{
		{ // Success
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {},
			assert: func(sut *BpfRecorder, err error) {
				require.Nil(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
		{ // Success with start
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Nil(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
		{ // Success with double start
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				_, err = sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Nil(t, err)
				require.EqualValues(t, 1, sut.startRequests)
			},
		},
	} {
		sut := New("", logr.Discard(), true, false)

		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		tc.prepare(sut, mock)

		_, err := sut.Stop(context.Background(), &api.EmptyRequest{})
		tc.assert(sut, err)
	}
}

func TestSyscallsForProfile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*BpfRecorder, *api.SyscallsResponse, error)
	}{
		{ // Success
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns([]byte{0, 1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "syscall_a", nil)
				mock.GetNameReturnsOnCall(1, "syscall_b", nil)
				mock.GetNameReturnsOnCall(2, "syscall_c", nil)
				mock.GetNameReturnsOnCall(3, "syscall_a", nil)
				mock.GetNameReturnsOnCall(4, "syscall_b", nil)
				mock.GetNameReturnsOnCall(5, "syscall_c", nil)
				mock.DeleteKeyReturnsOnCall(0, errTest)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Nil(t, err)
				require.Len(t, resp.Syscalls, 3)
				require.Equal(t, "syscall_a", resp.Syscalls[0])
				require.Equal(t, "syscall_b", resp.Syscalls[1])
				require.Equal(t, "syscall_c", resp.Syscalls[2])
			},
		},
		{ // Success with unable to resolve syscall name
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns([]byte{1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "", errTest)
				mock.GetNameReturnsOnCall(1, "syscall_a", nil)
				mock.GetNameReturnsOnCall(2, "syscall_b", nil)
				mock.GetNameReturnsOnCall(3, "syscall_a", nil)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Nil(t, err)
				require.Len(t, resp.Syscalls, 2)
				require.Equal(t, "syscall_a", resp.Syscalls[0])
				require.Equal(t, "syscall_b", resp.Syscalls[1])
			},
		},
		{ // recorder not running
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // not recording seccomp
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				sut.Seccomp = nil
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // no PID for container
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // no syscall found for profile
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns(nil, errTest)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // Failed to clean syscalls map
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns([]byte{1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "syscall_a", nil)
				mock.GetNameReturnsOnCall(1, "syscall_b", nil)
				mock.GetNameReturnsOnCall(2, "syscall_c", nil)
				mock.DeleteKeyReturns(errTest)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Nil(t, err)
				require.Len(t, resp.Syscalls, 3)
				require.Equal(t, "syscall_a", resp.Syscalls[0])
				require.Equal(t, "syscall_b", resp.Syscalls[1])
				require.Equal(t, "syscall_c", resp.Syscalls[2])
			},
		},
	} {
		sut := New("", logr.Discard(), true, false)

		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		tc.prepare(sut, mock)

		resp, err := sut.SyscallsForProfile(
			context.Background(), &api.ProfileRequest{Name: profile},
		)
		tc.assert(sut, resp, err)
	}
}

func TestApparmorForProfile(t *testing.T) {
	t.Parallel()

	mID := mntnsID(mntns)

	for _, tc := range []struct {
		prepare func(*BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*BpfRecorder, *api.ApparmorResponse, error)
	}{
		{ // Success
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				sut.AppArmor.recordedSocketsUse = map[mntnsID]*BpfAppArmorSocketTypes{
					mID: {
						UseRaw: false,
						UseTCP: true,
						UseUDP: false,
					},
				}
				sut.AppArmor.recordedCapabilities = map[mntnsID][]int{
					mID: {1, 2, 3},
				}
				sut.AppArmor.recordedFiles = map[mntnsID]map[string]*fileAccess{
					mID: {
						"/home/user/test": &fileAccess{spawn: true},
					},
				}
			},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.Nil(t, err)
				require.Len(t, resp.Capabilities, 3)
				require.Len(t, resp.Files.AllowedExecutables, 1)
				require.False(t, resp.Socket.UseRaw)
				require.True(t, resp.Socket.UseTcp)
				require.False(t, resp.Socket.UseUdp)
			},
		},
		{ // Success only for right mntns
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				sut.AppArmor.recordedSocketsUse = map[mntnsID]*BpfAppArmorSocketTypes{
					mID: {
						UseRaw: false,
						UseTCP: true,
						UseUDP: false,
					},
				}
				sut.AppArmor.recordedCapabilities = map[mntnsID][]int{
					mID: {1, 2, 3},
				}
				sut.AppArmor.recordedFiles = map[mntnsID]map[string]*fileAccess{
					mID: {
						"/home/user/test1": &fileAccess{spawn: true},
					},
					123: {
						"/home/user/test2": &fileAccess{spawn: true},
					},
				}
			},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.Nil(t, err)
				require.Len(t, resp.Capabilities, 3)
				require.Len(t, resp.Files.AllowedExecutables, 1)
				require.False(t, resp.Socket.UseRaw)
				require.True(t, resp.Socket.UseTcp)
				require.False(t, resp.Socket.UseUdp)
			},
		},
		{ // recorder not running
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // not recording apparmor
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				sut.AppArmor = nil
			},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // no PID for container
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
			},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.NotNil(t, err)
			},
		},
	} {
		sut := New("", logr.Discard(), true, true)

		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		// This is required to enable the unit tests when they are executed on an
		// Linux OS without BPF_LSM module enabled.
		t.Setenv("E2E_TEST_BPF_LSM_ENABLED", "1")

		tc.prepare(sut, mock)

		resp, err := sut.ApparmorForProfile(
			context.Background(), &api.ProfileRequest{Name: profile},
		)
		tc.assert(sut, resp, err)
	}
}

type Logger struct {
	messages []string
	mutex    sync.RWMutex
}

func (l *Logger) Init(logr.RuntimeInfo)                  {}
func (l *Logger) Enabled(int) bool                       { return true }
func (l *Logger) WithValues(...interface{}) logr.LogSink { return l }
func (l *Logger) WithName(string) logr.LogSink           { return l }

func (l *Logger) Info(_ int, msg string, _ ...interface{}) {
	l.mutex.Lock()
	l.messages = append(l.messages, msg)
	l.mutex.Unlock()
}

func (l *Logger) Error(_ error, msg string, _ ...interface{}) {
	l.mutex.Lock()
	l.messages = append(l.messages, msg)
	l.mutex.Unlock()
}

func TestProcessEvents(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, bpfEvent{
		Pid:   42,
		Mntns: 0x1010,
		Type:  uint8(eventTypeExit),
	})
	require.Nil(t, err)

	ch := make(chan []byte, 1)
	ch <- buf.Bytes()
	close(ch)

	go sut.processEvents(ch)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = sut.WaitForPidExit(ctx, 42)
	require.Nil(t, err)
}

func TestHandleEvent(t *testing.T) {
	t.Parallel()

	logSink := &Logger{}
	logger := logr.New(logSink)

	sut := New("", logger, true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock

	sut.handleEvent([]byte{1, 0, 0})

	logSink.mutex.RLock()
	require.Contains(t, logSink.messages, "Couldn't read event structure")
	logSink.mutex.RUnlock()
}

func TestNewPidEvent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*BpfRecorder, *bpfrecorderfakes.FakeImpl) bpfEvent
		assert  func(*BpfRecorder, *Logger)
	}{
		{ // Success
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) bpfEvent {
				mock.ContainerIDForPIDReturns(containerID, nil)
				mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pod,
						Namespace: namespace,
						Annotations: map[string]string{
							config.SeccompProfileRecordBpfAnnotationKey + "ctr": "profile.json",
						},
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefix + containerID,
							Name:        "ctr",
						}},
					},
				}}}, nil)
				return bpfEvent{
					Pid:   42,
					Mntns: 0x1010,
					Type:  uint8(eventTypeNewPid),
				}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				var foundMntns uint32
				for i := 0; i < 100; i++ {
					if containerID, ok := sut.containerIDToProfileMap.GetBackwards("profile.json"); ok {
						if actualMntns, ok := sut.mntnsToContainerIDMap.GetBackwards(containerID); ok {
							foundMntns = actualMntns
							break
						}
					}
					time.Sleep(100 * time.Millisecond)
				}
				require.Equal(t, uint32(0x1010), foundMntns)
			},
		},
		{ // unable to find container ID for PID
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) bpfEvent {
				mock.ContainerIDForPIDReturns(containerID, errTest)
				return bpfEvent{
					Pid:   42,
					Mntns: 0x1010,
					Type:  uint8(eventTypeNewPid),
				}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				success := false
				for i := 0; i < 100; i++ {
					logger.mutex.RLock()
					success = util.Contains(logger.messages, "No container ID found for PID")
					logger.mutex.RUnlock()
					if success {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				require.True(t, success)
			},
		},
		{ // unable to find profile in cluster for container ID
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) bpfEvent {
				mock.ContainerIDForPIDReturns(containerID, nil)
				mock.ListPodsReturns(nil, errTest)
				return bpfEvent{
					Pid:   42,
					Mntns: 0x1010,
					Type:  uint8(eventTypeNewPid),
				}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				success := false
				for i := 0; i < 100; i++ {
					logger.mutex.RLock()
					success = util.Contains(logger.messages, "Unable to find profile in cluster for container ID")
					logger.mutex.RUnlock()
					if success {
						break
					}
					time.Sleep(200 * time.Millisecond)
				}
				require.True(t, success)
			},
		},
	} {
		logSink := &Logger{}
		logger := logr.New(logSink)
		sut := New("", logger, false, false)
		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock
		// pretend that we're running in a kubernetes context
		sut.clientset = &kubernetes.Clientset{}

		e := tc.prepare(sut, mock)

		go sut.handleNewPidEvent(&e)

		tc.assert(sut, logSink)
	}
}
