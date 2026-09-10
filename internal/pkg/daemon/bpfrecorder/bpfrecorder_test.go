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

package bpfrecorder

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
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
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
				mock.DialMetricsReturns(&grpc.ClientConn{}, nil)
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{ // Getenv returns nothing
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns("")
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // InClusterConfig fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.InClusterConfigReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // NewForConfig fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.NewForConfigReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // RemoveAll fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.RemoveAllReturns(errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // Listen fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // Chown fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ChownReturns(errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // connectMetrics:DialMetrics fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.DialMetricsReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // connectMetrics:BpfIncClient fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.DialMetricsReturns(&grpc.ClientConn{}, nil)
				mock.CloseGRPCReturns(errTest)
				mock.BpfIncClientReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // Readlink fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ReadlinkReturns("", errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // Atoi fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ParseUintReturns(0, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // ServeFails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.ServeReturns(errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load wrong GOARCH
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns("invalid")
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load:NewModuleFromBufferArgs fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load:InitGlobalVariable fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.InitGlobalVariableReturns(errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load:BPFLoadObject fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.BPFLoadObjectReturns(errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load:GetProgram fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetProgramReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load:AttachGeneric fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.AttachGenericReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // load:GetMap fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetMapReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},

		{ // load:InitRingBuf fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.InitRingBufReturns(nil, errTest)
			},
			assert: func(err error) {
				require.Error(t, err)
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

func TestLoad(t *testing.T) {
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
				require.NoError(t, err)
			},
		},
		{ // load failed wrong GOARCH
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns("invalid")
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Error(t, err)
			},
		},
		{ // Error attaching
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.AttachGenericReturns(nil, errTest)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Error(t, err)
			},
		},
	} {
		mock := &bpfrecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := New("", logr.Discard(), true, true)
		sut.impl = mock

		err := sut.Load()
		tc.assert(sut, err)
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
			},
			assert: func(sut *BpfRecorder, err error) {
				require.NoError(t, err)
				require.EqualValues(t, 1, sut.startRequests)
			},
		},
		{ // Success already running
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
			},
			assert: func(sut *BpfRecorder, err error) {
				require.NoError(t, err)
				require.EqualValues(t, 1, sut.startRequests)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				require.EqualValues(t, 2, sut.startRequests)
			},
		},
		{ // Error attaching
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.UpdateValueReturns(errTest)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.Error(t, err)
			},
		},
	} {
		mock := &bpfrecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := New("", logr.Discard(), true, true)
		sut.impl = mock

		mock.GoArchReturns(validGoArch)
		mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

		err := sut.Load()
		require.NoError(t, err)

		_, err = sut.Start(t.Context(), &api.EmptyRequest{})
		tc.assert(sut, err)
	}
}

func TestStartNotLoaded(t *testing.T) {
	t.Parallel()

	mock := &bpfrecorderfakes.FakeImpl{}
	sut := New("", logr.Discard(), true, true)
	sut.impl = mock
	err := sut.StartRecording()
	require.Equal(t, err, ErrStartBeforeLoad)
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
				require.NoError(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
		{ // Success with start
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.NoError(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
		{ // Success with double start
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(sut *BpfRecorder, err error) {
				require.NoError(t, err)
				require.EqualValues(t, 1, sut.startRequests)
			},
		},
	} {
		sut := New("", logr.Discard(), true, false)

		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		tc.prepare(sut, mock)

		_, err := sut.Stop(t.Context(), &api.EmptyRequest{})
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
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
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
				require.NoError(t, err)
				require.Len(t, resp.GetSyscalls(), 3)
				require.Equal(t, "syscall_a", resp.GetSyscalls()[0])
				require.Equal(t, "syscall_b", resp.GetSyscalls()[1])
				require.Equal(t, "syscall_c", resp.GetSyscalls()[2])
			},
		},
		{ // Success with unable to resolve syscall name
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns([]byte{1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "", errTest)
				mock.GetNameReturnsOnCall(1, "syscall_a", nil)
				mock.GetNameReturnsOnCall(2, "syscall_b", nil)
				mock.GetNameReturnsOnCall(3, "syscall_a", nil)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NoError(t, err)
				require.Len(t, resp.GetSyscalls(), 2)
				require.Equal(t, "syscall_a", resp.GetSyscalls()[0])
				require.Equal(t, "syscall_b", resp.GetSyscalls()[1])
			},
		},
		{ // recorder not running
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Error(t, err)
			},
		},
		{ // not recording seccomp
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				sut.Seccomp = nil
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Error(t, err)
			},
		},
		{ // no PID for container
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Error(t, err)
			},
		},
		{ // no syscall found for profile
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns(nil, errTest)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Error(t, err)
			},
		},
		{ // Failed to clean syscalls map
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.mntnsToContainerIDMap.Insert(mntns, containerID)
				mock.GetValueReturns([]byte{1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "syscall_a", nil)
				mock.GetNameReturnsOnCall(1, "syscall_b", nil)
				mock.GetNameReturnsOnCall(2, "syscall_c", nil)
				mock.DeleteKeyReturns(errTest)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NoError(t, err)
				require.Len(t, resp.GetSyscalls(), 3)
				require.Equal(t, "syscall_a", resp.GetSyscalls()[0])
				require.Equal(t, "syscall_b", resp.GetSyscalls()[1])
				require.Equal(t, "syscall_c", resp.GetSyscalls()[2])
			},
		},
	} {
		sut := New("", logr.Discard(), true, false)

		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		tc.prepare(sut, mock)

		resp, err := sut.SyscallsForProfile(
			t.Context(), &api.ProfileRequest{Name: profile},
		)
		tc.assert(sut, resp, err)
	}
}

func TestApparmorForProfile(t *testing.T) {
	t.Parallel()

	mID := mntnsID(mntns)

	for _, tc := range []struct {
		name    string
		prepare func(*BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*BpfRecorder, *api.ApparmorResponse, error)
	}{
		{ // Success
			name: "success",
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
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
				require.NoError(t, err)
				require.Len(t, resp.GetCapabilities(), 3)
				require.Len(t, resp.GetFiles().GetAllowedExecutables(), 1)
				require.False(t, resp.GetSocket().GetUseRaw())
				require.True(t, resp.GetSocket().GetUseTcp())
				require.False(t, resp.GetSocket().GetUseUdp())
			},
		},
		{ // Success only for right mntns
			name: "success only for right mntns",
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
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
				require.NoError(t, err)
				require.Len(t, resp.GetCapabilities(), 3)
				require.Len(t, resp.GetFiles().GetAllowedExecutables(), 1)
				require.False(t, resp.GetSocket().GetUseRaw())
				require.True(t, resp.GetSocket().GetUseTcp())
				require.False(t, resp.GetSocket().GetUseUdp())
			},
		},
		{ // recorder not running
			name:    "recorder not running",
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.Error(t, err)
			},
		},
		{ // not recording apparmor
			name: "apparmor recorder disabled",
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				sut.AppArmor = nil
			},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.Error(t, err)
			},
		},
		{ // no PID for container
			name: "no pid for container available",
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New("", logr.Discard(), true, true)

			mock := &bpfrecorderfakes.FakeImpl{}
			sut.impl = mock

			tc.prepare(sut, mock)

			resp, err := sut.ApparmorForProfile(
				t.Context(), &api.ProfileRequest{Name: profile},
			)
			tc.assert(sut, resp, err)
		})
	}
}

type Logger struct {
	messages []string
	mutex    sync.RWMutex
}

func (l *Logger) Init(logr.RuntimeInfo)          {}
func (l *Logger) Enabled(int) bool               { return true }
func (l *Logger) WithValues(...any) logr.LogSink { return l }
func (l *Logger) WithName(string) logr.LogSink   { return l }

func (l *Logger) Info(_ int, msg string, _ ...any) {
	l.mutex.Lock()
	l.messages = append(l.messages, msg)
	l.mutex.Unlock()
}

func (l *Logger) Error(_ error, msg string, _ ...any) {
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
	require.NoError(t, err)

	ch := make(chan []byte, 1)
	ch <- buf.Bytes()

	close(ch)

	go sut.processEvents(ch)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	err = sut.WaitForPidExit(ctx, 42)
	require.NoError(t, err)
}

// TestRecordedExitsAreBounded asserts that exit events do not accumulate
// forever. In-cluster nobody calls WaitForPidExit, so without a bound every
// recorded process exit would leak an entry for the daemon's lifetime.
func TestRecordedExitsAreBounded(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	sut.impl = &bpfrecorderfakes.FakeImpl{}

	for pid := range uint32(maxCacheItems * 2) {
		sut.handleExitEvent(&bpfEvent{Pid: pid, Type: uint8(eventTypeExit)})
	}

	require.LessOrEqual(t, uint64(sut.recentExits.Len()), maxCacheItems)
}

// TestWaitForPidExitSurvivesEviction asserts that a parked waiter is still
// woken when the recorded exits are evicted or cleared underneath it. The
// waiter owns its channel, so it cannot be dropped from the bounded cache.
func TestWaitForPidExitSurvivesEviction(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	sut.impl = &bpfrecorderfakes.FakeImpl{}

	const pid uint32 = 42

	waitErr := make(chan error, 1)

	go func() {
		waitErr <- sut.WaitForPidExit(t.Context(), pid)
	}()

	// Let the waiter register, then churn the cache past its capacity and clear
	// it, which is what StopRecording does.
	require.Eventually(t, func() bool {
		_, ok := sut.exitWaiters.Load(pid)

		return ok
	}, time.Minute, time.Millisecond)

	for other := range uint32(maxCacheItems + 10) {
		sut.recentExits.Set(other+1000, struct{}{}, ttlcache.DefaultTTL)
	}

	sut.recentExits.DeleteAll()

	sut.handleExitEvent(&bpfEvent{Pid: pid, Type: uint8(eventTypeExit)})

	select {
	case err := <-waitErr:
		require.NoError(t, err)
	case <-time.After(time.Minute):
		t.Fatal("waiter was not woken after the recorded exits were evicted")
	}
}

// TestStopRecordingReleasesLookupTables asserts that the per-session lookup
// tables are released once no recording is in progress any more.
func TestStopRecordingReleasesLookupTables(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), false, false)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock

	sut.mntnsToContainerIDMap.Insert(0x1010, "container-id")
	sut.containerIDToProfileMap.Insert("container-id", "profile")
	sut.handleExitEvent(&bpfEvent{Pid: 42, Type: uint8(eventTypeExit)})

	require.Equal(t, 1, sut.mntnsToContainerIDMap.Size())
	require.Equal(t, 1, sut.containerIDToProfileMap.Size())
	require.Equal(t, 1, sut.recentExits.Len())

	require.NoError(t, sut.StopRecording())

	require.Equal(t, 0, sut.mntnsToContainerIDMap.Size())
	require.Equal(t, 0, sut.containerIDToProfileMap.Size())
	require.Equal(t, 0, sut.recentExits.Len())
}

// TestHandlerFromFinishedRecordingIsDiscarded asserts that a handler still in
// flight when a recording stops cannot repopulate the lookup tables afterwards.
func TestHandlerFromFinishedRecordingIsDiscarded(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), false, false)
	sut.impl = &bpfrecorderfakes.FakeImpl{}
	sut.clientset = &kubernetes.Clientset{}

	staleGeneration := sut.recordingGeneration.Load()

	require.NoError(t, sut.StopRecording())

	sut.handleNewPidEvent(42, 0x1010, staleGeneration)

	require.Equal(t, 0, sut.mntnsToContainerIDMap.Size(),
		"a handler from a finished recording must not repopulate the tables")
}

// TestWaitForPidExitWakesConcurrentWaiters asserts that every caller waiting on
// the same pid is woken. Registering with Store rather than LoadOrStore used to
// drop the earlier waiters, leaving them parked until their context expired.
func TestWaitForPidExitWakesConcurrentWaiters(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	sut.impl = &bpfrecorderfakes.FakeImpl{}

	const (
		pid     uint32 = 42
		waiters int    = 4
	)

	errs := make(chan error, waiters)

	for range waiters {
		go func() {
			errs <- sut.WaitForPidExit(t.Context(), pid)
		}()
	}

	// Wait until every caller is registered on the shared channel.
	require.Eventually(t, func() bool {
		waiter, ok := sut.exitWaiters.Load(pid)
		if !ok {
			return false
		}

		done, ok := waiter.(chan struct{})

		return ok && done != nil
	}, time.Minute, time.Millisecond)

	sut.handleExitEvent(&bpfEvent{Pid: pid, Type: uint8(eventTypeExit)})

	for range waiters {
		select {
		case err := <-errs:
			require.NoError(t, err)
		case <-time.After(time.Minute):
			t.Fatal("a concurrent waiter was never woken")
		}
	}
}

// TestScheduleNewPidEventDropsWhenSaturated asserts that a full queue drops the
// event instead of stalling the event processing loop. That loop also delivers
// the AppArmor events, so blocking it makes the kernel drop recorded events.
func TestScheduleNewPidEventDropsWhenSaturated(t *testing.T) {
	t.Parallel()

	logSink := &Logger{}
	sut := New("", logr.New(logSink), true, true)
	sut.impl = &bpfrecorderfakes.FakeImpl{}

	// Fill the queue without starting the handlers.
	sut.startPidHandlers.Do(func() {})

	for range newPidQueueSize {
		sut.newPidEvents <- newPidEvent{}
	}

	done := make(chan struct{})

	go func() {
		defer close(done)

		sut.scheduleNewPidEvent(42, 0x1010)
	}()

	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("scheduleNewPidEvent blocked on a full queue")
	}

	logSink.mutex.RLock()
	defer logSink.mutex.RUnlock()

	require.Contains(t, logSink.messages,
		"Dropping new pid event because the handler queue is full")
}

// TestScheduleNewPidEventRunsHandler asserts the normal path still dispatches.
func TestScheduleNewPidEventRunsHandler(t *testing.T) {
	t.Parallel()

	logSink := &Logger{}
	sut := New("", logr.New(logSink), true, true)
	sut.impl = &bpfrecorderfakes.FakeImpl{}

	sut.scheduleNewPidEvent(42, 0x1010)

	require.Eventually(t, func() bool {
		logSink.mutex.RLock()
		defer logSink.mutex.RUnlock()

		return slices.Contains(logSink.messages, "Received new pid")
	}, time.Minute, time.Millisecond)
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

				for range 100 {
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

				for range 100 {
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

				for range 100 {
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

		go sut.handleNewPidEvent(e.Pid, e.Mntns, sut.recordingGeneration.Load())

		tc.assert(sut, logSink)
	}
}
