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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	seccomp "github.com/seccomp/libseccomp-golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
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
		name    string
		prepare func(*testing.T, *bpfrecorderfakes.FakeImpl)
		assert  func(*testing.T, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
				mock.DialMetricsReturns(&grpc.ClientConn{}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "InClusterConfig fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.InClusterConfigReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "NewForConfig fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewForConfigReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "RemoveAll fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.RemoveAllReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "Listen fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.ListenReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "Chown fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.ChownReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "connectMetrics DialMetrics fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.DialMetricsReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "connectMetrics BpfIncClient fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.DialMetricsReturns(&grpc.ClientConn{}, nil)
				mock.CloseGRPCReturns(errTest)
				mock.BpfIncClientReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "Readlink fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.ReadlinkReturns("", errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "ParseUint fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.ReadlinkReturns("mnt:[invalid]", nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "Serve fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.ServeReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "load NewModuleFromBufferArgs fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "load InitGlobalVariable fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.InitGlobalVariableReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "load BPFLoadObject fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.BPFLoadObjectReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "load GetProgram fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.GetProgramReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "load AttachGeneric fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.AttachGenericReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "load GetMap fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.GetMapReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},

		{
			name: "load InitRingBuf fails",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.InitRingBufReturns(nil, errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bpfrecorderfakes.FakeImpl{}
			mock.ReadlinkReturns("mnt:[4026531841]", nil)
			mock.PodListerWatcherReturns(podindextest.New())

			listener := &fakeListener{}
			listened := false
			mock.ListenStub = func(string, string) (net.Listener, error) {
				listened = true

				return listener, nil
			}

			tc.prepare(t, mock)

			sut := New("test", logr.Discard(), true, false)
			sut.impl = mock
			sut.nodeName = node

			err := sut.Run()
			tc.assert(t, err)

			// Serve takes over the listener, otherwise Run has to close it.
			if listened {
				require.Equal(t, mock.ServeCallCount() == 0, listener.closed.Load())
			}
		})
	}
}

// fakeListener records whether it got closed.
type fakeListener struct {
	net.Listener

	closed atomic.Bool
}

func (l *fakeListener) Close() error {
	l.closed.Store(true)

	return nil
}

func TestRunWithoutNodeName(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, "")

	sut := New("test", logr.Discard(), true, false)
	sut.impl = &bpfrecorderfakes.FakeImpl{}

	require.Error(t, sut.Run())
}

func TestBpfObjectForArch(t *testing.T) {
	t.Parallel()

	for _, arch := range []string{"amd64", "arm64"} {
		object, err := bpfObjectForArch(arch)
		require.NoError(t, err)
		require.NotEmpty(t, object)
	}

	_, err := bpfObjectForArch("invalid")
	require.Error(t, err)
}

func TestLoad(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *bpfrecorderfakes.FakeImpl)
		assert  func(*testing.T, *BpfRecorder, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "error attaching",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.AttachGenericReturns(nil, errTest)
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bpfrecorderfakes.FakeImpl{}
			tc.prepare(t, mock)

			sut := New("", logr.Discard(), true, true)
			sut.impl = mock

			err := sut.Load()
			tc.assert(t, sut, err)
		})
	}
}

func TestStart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *bpfrecorderfakes.FakeImpl)
		assert  func(*testing.T, *BpfRecorder, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.NoError(t, err)
				require.EqualValues(t, 1, sut.startRequests)
			},
		},
		{
			name: "success already running",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.NoError(t, err)
				require.EqualValues(t, 1, sut.startRequests)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				require.EqualValues(t, 2, sut.startRequests)
			},
		},
		{
			name: "error attaching",
			prepare: func(t *testing.T, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.UpdateValueReturns(errTest)
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &bpfrecorderfakes.FakeImpl{}
			tc.prepare(t, mock)

			sut := New("", logr.Discard(), true, true)
			sut.impl = mock

			mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

			err := sut.Load()
			require.NoError(t, err)

			_, err = sut.Start(t.Context(), &api.EmptyRequest{})
			tc.assert(t, sut, err)
		})
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
		name    string
		prepare func(*testing.T, *BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*testing.T, *BpfRecorder, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.NoError(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
		{
			name: "success with start",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.NoError(t, err)
				require.EqualValues(t, 0, sut.startRequests)
			},
		},
		{
			name: "success with double start",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, sut *BpfRecorder, err error) {
				t.Helper()

				require.NoError(t, err)
				require.EqualValues(t, 1, sut.startRequests)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New("", logr.Discard(), true, false)

			mock := &bpfrecorderfakes.FakeImpl{}
			sut.impl = mock

			tc.prepare(t, sut, mock)

			_, err := sut.Stop(t.Context(), &api.EmptyRequest{})
			tc.assert(t, sut, err)
		})
	}
}

func TestSyscallsForProfile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*testing.T, *BpfRecorder, *api.SyscallsResponse, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
				mock.GetValue64Returns([]byte{0, 1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "syscall_a", nil)
				mock.GetNameReturnsOnCall(1, "syscall_b", nil)
				mock.GetNameReturnsOnCall(2, "syscall_c", nil)
				mock.GetNameReturnsOnCall(3, "syscall_a", nil)
				mock.GetNameReturnsOnCall(4, "syscall_b", nil)
				mock.GetNameReturnsOnCall(5, "syscall_c", nil)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, resp.GetSyscalls(), 3)
				require.Equal(t, "syscall_a", resp.GetSyscalls()[0])
				require.Equal(t, "syscall_b", resp.GetSyscalls()[1])
				require.Equal(t, "syscall_c", resp.GetSyscalls()[2])
			},
		},
		{
			name: "success with unable to resolve syscall name",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
				mock.GetValue64Returns([]byte{1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "", errTest)
				mock.GetNameReturnsOnCall(1, "syscall_a", nil)
				mock.GetNameReturnsOnCall(2, "syscall_b", nil)
				mock.GetNameReturnsOnCall(3, "syscall_a", nil)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, resp.GetSyscalls(), 2)
				require.Equal(t, "syscall_a", resp.GetSyscalls()[0])
				require.Equal(t, "syscall_b", resp.GetSyscalls()[1])
			},
		},
		{
			name: "recorder not running",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.ErrorIs(t, err, errNotRunning)
				require.Equal(t, codes.FailedPrecondition, status.Code(err))
			},
		},
		{
			name: "not recording seccomp",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				sut.Seccomp = nil
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "no PID for container",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrNotFound)
				require.Equal(t, codes.NotFound, status.Code(err))
				require.Equal(t, ErrNotFound.Error(), status.Convert(err).Message())
			},
		},
		{
			name: "no syscall found for profile",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
				mock.GetValue64Returns(nil, errTest)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "reading does not remove the syscalls",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
				mock.GetValue64Returns([]byte{1, 1, 1}, nil)
				mock.GetNameReturnsOnCall(0, "syscall_a", nil)
				mock.GetNameReturnsOnCall(1, "syscall_b", nil)
				mock.GetNameReturnsOnCall(2, "syscall_c", nil)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				t.Helper()

				require.NoError(t, err)

				mock, ok := sut.impl.(*bpfrecorderfakes.FakeImpl)
				require.True(t, ok)
				require.Zero(t, mock.DeleteKey64CallCount())
				require.Len(t, resp.GetSyscalls(), 3)
				require.Equal(t, "syscall_a", resp.GetSyscalls()[0])
				require.Equal(t, "syscall_b", resp.GetSyscalls()[1])
				require.Equal(t, "syscall_c", resp.GetSyscalls()[2])
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New("", logr.Discard(), true, false)

			mock := &bpfrecorderfakes.FakeImpl{}
			sut.impl = mock

			tc.prepare(t, sut, mock)

			resp, err := sut.SyscallsForProfile(
				t.Context(), &api.ProfileRequest{Name: profile},
			)
			tc.assert(t, sut, resp, err)
		})
	}
}

func TestApparmorForProfile(t *testing.T) {
	t.Parallel()

	mID := recordingKey(mntns)

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *BpfRecorder, *bpfrecorderfakes.FakeImpl)
		assert  func(*testing.T, *BpfRecorder, *api.ApparmorResponse, error)
	}{
		{ // Success
			name: "success",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
				sut.AppArmor.recordedSocketsUse = map[recordingKey]*BpfAppArmorSocketTypes{
					mID: {
						UseRaw: false,
						UseTCP: true,
						UseUDP: false,
					},
				}
				sut.AppArmor.recordedCapabilities = map[recordingKey][]int{
					mID: {1, 2, 3},
				}
				sut.AppArmor.recordedFiles = map[recordingKey]map[string]*fileAccess{
					mID: {
						"/home/user/test": &fileAccess{spawn: true},
					},
				}
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				t.Helper()

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
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
				sut.AppArmor.recordedSocketsUse = map[recordingKey]*BpfAppArmorSocketTypes{
					mID: {
						UseRaw: false,
						UseTCP: true,
						UseUDP: false,
					},
				}
				sut.AppArmor.recordedCapabilities = map[recordingKey][]int{
					mID: {1, 2, 3},
				}
				sut.AppArmor.recordedFiles = map[recordingKey]map[string]*fileAccess{
					mID: {
						"/home/user/test1": &fileAccess{spawn: true},
					},
					123: {
						"/home/user/test2": &fileAccess{spawn: true},
					},
				}
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, resp.GetCapabilities(), 3)
				require.Len(t, resp.GetFiles().GetAllowedExecutables(), 1)
				require.False(t, resp.GetSocket().GetUseRaw())
				require.True(t, resp.GetSocket().GetUseTcp())
				require.False(t, resp.GetSocket().GetUseUdp())
			},
		},
		{ // recorder not running
			name: "recorder not running",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{ // not recording apparmor
			name: "apparmor recorder disabled",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				sut.AppArmor = nil
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "no BPF LSM",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
				mock.BPFLSMEnabledReturns(false)

				require.NoError(t, sut.Load())
				_, err := sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
				sut.containerIDToProfileMap.Insert(containerID, profile)
				sut.containerKeys.Insert(uint64(mntns), containerID)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				t.Helper()

				require.Equal(t, codes.FailedPrecondition, status.Code(err))
				require.ErrorIs(t, err, ErrAppArmorUnavailable)
				require.ErrorIs(t, err, errBPFLSMDisabled)
			},
		},
		{ // no PID for container
			name: "no pid for container available",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				t.Helper()

				mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

				err := sut.Load()
				require.NoError(t, err)
				_, err = sut.Start(t.Context(), &api.EmptyRequest{})
				require.NoError(t, err)
			},
			assert: func(t *testing.T, sut *BpfRecorder, resp *api.ApparmorResponse, err error) {
				t.Helper()

				require.Equal(t, codes.NotFound, status.Code(err))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut := New("", logr.Discard(), true, true)

			mock := &bpfrecorderfakes.FakeImpl{}
			mock.BPFLSMEnabledReturns(true)
			sut.impl = mock

			tc.prepare(t, sut, mock)

			resp, err := sut.ApparmorForProfile(
				t.Context(), &api.ProfileRequest{Name: profile},
			)
			tc.assert(t, sut, resp, err)
		})
	}
}

// TestRPCError asserts the status codes the profile recorder acts on, and that
// the messages stay the same.
func TestRPCError(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "nil", err: nil, code: codes.OK},
		{name: "not found", err: ErrNotFound, code: codes.NotFound},
		{
			name: "wrapped not found",
			err:  fmt.Errorf("read syscalls: %w", ErrNotFound),
			code: codes.NotFound,
		},
		{name: "not running", err: errNotRunning, code: codes.FailedPrecondition},
		{name: "no seccomp recording", err: errNoSeccompRecording, code: codes.FailedPrecondition},
		{name: "no apparmor recording", err: errNoAppArmorRecording, code: codes.FailedPrecondition},
		{
			name: "apparmor unavailable",
			err:  fmt.Errorf("%w: %w", ErrAppArmorUnavailable, errTest),
			code: codes.FailedPrecondition,
		},
		{
			name: "status error is kept",
			err:  status.Error(codes.InvalidArgument, "invalid"),
			code: codes.InvalidArgument,
		},
		{name: "other error", err: errTest, code: codes.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := rpcError(tc.err)
			require.Equal(t, tc.code, status.Code(err))

			if tc.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.err)
			require.Equal(t, status.Convert(tc.err).Message(), status.Convert(err).Message())
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

// snapshot returns a copy of the recorded messages.
func (l *Logger) snapshot() []string {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return slices.Clone(l.messages)
}

// requireLogged waits for msg to be logged. The recorder handles events on its
// own goroutines, so the assertion has to poll; on failure it reports what was
// actually logged instead of a bare "false".
func requireLogged(t *testing.T, logger *Logger, msg string) {
	t.Helper()

	// The lookup this waits on retries with backoff, so the deadline has to
	// cover the whole retry sequence rather than a fixed number of polls.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Contains(c, logger.snapshot(), msg)
	}, 30*time.Second, 20*time.Millisecond)
}

func TestProcessEvents(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock

	event := make([]byte, bpfEventHeaderSize)
	binary.LittleEndian.PutUint32(event[0:], 42)
	binary.LittleEndian.PutUint32(event[4:], 0x1010)
	event[16] = uint8(eventTypeExit)

	ch := make(chan []byte, 1)
	ch <- event

	close(ch)

	go sut.processEvents(ch)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	err := sut.WaitForPidExit(ctx, 42)
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

	sut.containerKeys.Insert(0x1010, "container-id")
	sut.containerIDToProfileMap.Insert("container-id", "profile")
	sut.containersWithoutProfile.Set("other-container", struct{}{}, ttlcache.DefaultTTL)
	sut.handleExitEvent(&bpfEvent{Pid: 42, Type: uint8(eventTypeExit)})

	require.Equal(t, 1, sut.containerKeys.Size())
	require.Equal(t, 1, sut.containerIDToProfileMap.Size())
	require.Equal(t, 1, sut.recentExits.Len())
	require.Equal(t, 1, sut.containersWithoutProfile.Len())

	require.NoError(t, sut.StopRecording())

	require.Equal(t, 0, sut.containerKeys.Size())
	require.Equal(t, 0, sut.containerIDToProfileMap.Size())
	require.Equal(t, 0, sut.recentExits.Len())

	// The negative cache is per session too: a pod update can add recording
	// annotations to a container that is already running, and an entry kept
	// from the previous session would suppress the lookup for its whole TTL.
	require.Equal(t, 0, sut.containersWithoutProfile.Len())
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

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 0x1010, key: 0x1010, generation: staleGeneration},
	)

	require.Equal(t, 0, sut.containerKeys.Size(),
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

		sut.scheduleNewPidEvent(42, 0x1010, 0x1010, 0)
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

	sut.scheduleNewPidEvent(42, 0x1010, 0x1010, 0)

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
		name    string
		prepare func(*testing.T, *BpfRecorder, *bpfrecorderfakes.FakeImpl) bpfEvent
		assert  func(*testing.T, *BpfRecorder, *Logger)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) bpfEvent {
				t.Helper()

				mock.ContainerIDForPIDReturns(containerID, nil)
				watchPods(t, sut, podWithContainer(map[string]string{
					config.SeccompProfileRecordBpfAnnotationKey + "ctr": "profile.json",
				}))

				return bpfEvent{
					Pid:   42,
					Mntns: 0x1010,
					Key:   0x1010,
					Type:  uint8(eventTypeNewPid),
				}
			},
			assert: func(t *testing.T, sut *BpfRecorder, logger *Logger) {
				t.Helper()

				var foundKeys []uint64

				require.Eventually(t, func() bool {
					containerIDs := sut.containerIDToProfileMap.Containers("profile.json")
					foundKeys = sut.containerKeys.KeysOf(containerIDs)

					return len(foundKeys) > 0
				}, 10*time.Second, 10*time.Millisecond)

				require.Equal(t, []uint64{0x1010}, foundKeys)
			},
		},
		{
			name: "unable to find container ID for PID",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) bpfEvent {
				t.Helper()

				mock.ContainerIDForPIDReturns(containerID, errTest)

				return bpfEvent{
					Pid:   42,
					Mntns: 0x1010,
					Key:   0x1010,
					Type:  uint8(eventTypeNewPid),
				}
			},
			assert: func(t *testing.T, sut *BpfRecorder, logger *Logger) {
				t.Helper()

				requireLogged(t, logger, "No container ID found for PID")
			},
		},
		{
			name: "no pod has the container",
			prepare: func(t *testing.T, sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) bpfEvent {
				t.Helper()

				mock.ContainerIDForPIDReturns(containerID, nil)
				watchPods(t, sut)

				return bpfEvent{
					Pid:   42,
					Mntns: 0x1010,
					Key:   0x1010,
					Type:  uint8(eventTypeNewPid),
				}
			},
			assert: func(t *testing.T, sut *BpfRecorder, logger *Logger) {
				t.Helper()

				requireLogged(t, logger, "Container not found in cluster")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logSink := &Logger{}
			logger := logr.New(logSink)
			sut := New("", logger, false, false)
			mock := &bpfrecorderfakes.FakeImpl{}
			sut.impl = mock
			// pretend that we're running in a kubernetes context
			sut.clientset = &kubernetes.Clientset{}

			e := tc.prepare(t, sut, mock)

			go sut.handleNewPidEvent(
				newPidEvent{
					pid:        e.Pid,
					mntns:      e.Mntns,
					key:        e.Key,
					generation: sut.recordingGeneration.Load(),
				},
			)

			tc.assert(t, sut, logSink)
		})
	}
}

// TestTrackProfileMetricSerializesSends asserts that concurrent pid handlers
// never call Send on the shared metrics stream at the same time, which gRPC
// does not allow.
func TestTrackProfileMetricSerializesSends(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.DialMetricsReturns(&grpc.ClientConn{}, nil)
	sut.impl = mock

	var inFlight, overlaps atomic.Int32

	mock.SendMetricCalls(func(apimetrics.Metrics_BpfIncClient, *apimetrics.BpfRequest) error {
		if inFlight.Add(1) > 1 {
			overlaps.Add(1)
		}

		time.Sleep(time.Millisecond)
		inFlight.Add(-1)

		return nil
	})

	require.NoError(t, sut.connectMetrics(t.Context()))

	go sut.metrics.Run(t.Context())

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			sut.trackProfileMetric(uint32(i), "profile")
		})
	}

	wg.Wait()

	require.Eventually(t, func() bool {
		return mock.SendMetricCallCount() == 10
	}, time.Minute, time.Millisecond)
	require.Zero(t, overlaps.Load())
}

// TestTrackProfileMetricReconnects asserts that a broken metrics stream, for
// example after the metrics server restarted, is opened again instead of
// failing every later update.
func TestTrackProfileMetricReconnects(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.DialMetricsReturns(&grpc.ClientConn{}, nil)
	mock.SendMetricReturnsOnCall(0, errTest)
	sut.impl = mock

	require.NoError(t, sut.connectMetrics(t.Context()))
	require.Equal(t, 1, mock.DialMetricsCallCount())

	go sut.metrics.Run(t.Context())

	sut.trackProfileMetric(1, "profile")

	require.Eventually(t, func() bool {
		return mock.SendMetricCallCount() == 2
	}, time.Minute, time.Millisecond)
	require.Equal(t, 2, mock.DialMetricsCallCount())
	require.Equal(t, 1, mock.CloseGRPCCallCount())
}

func newRecordingRecorder(
	t *testing.T,
	recordSeccomp, recordAppArmor bool,
) (*BpfRecorder, *bpfrecorderfakes.FakeImpl) {
	t.Helper()

	sut := New("", logr.Discard(), recordSeccomp, recordAppArmor)
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	sut.impl = mock

	require.NoError(t, sut.Load())

	_, err := sut.Start(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)

	return sut, mock
}

// TestResetSyscallsForProfile asserts that the recorded syscalls are only
// dropped once the profile got stored, and that a retried collection of a
// stored profile does not wait for data which is gone.
func TestResetSyscallsForProfile(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, true)

	sut.containerIDToProfileMap.Insert(containerID, profile)
	sut.containerIDToProfileMap.Insert(containerID, "apparmor-profile")
	sut.containerKeys.Insert(1, containerID)
	sut.containerKeys.Insert(2, containerID)

	_, err := sut.ResetSyscallsForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.NoError(t, err)

	require.Equal(t, 2, mock.DeleteKey64CallCount())

	_, key := mock.DeleteKey64ArgsForCall(0)
	require.Equal(t, uint64(1), key)

	_, key = mock.DeleteKey64ArgsForCall(1)
	require.Equal(t, uint64(2), key)

	// The AppArmor profile of the same container is still to be collected.
	require.Equal(t, []uint64{1, 2}, sut.containerKeys.Keys(containerID))

	start := time.Now()
	_, err = sut.SyscallsForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.ErrorIs(t, err, ErrNotFound)
	require.Less(
		t,
		time.Since(start),
		time.Second,
		"a collected profile must not be looked up again",
	)

	_, err = sut.ResetApparmorForProfile(t.Context(), &api.ProfileRequest{Name: "apparmor-profile"})
	require.NoError(t, err)
	require.Empty(t, sut.containerKeys.Keys(containerID))

	// Starting a new recording forgets the collected profiles.
	require.NoError(t, sut.StopRecording())

	_, collected := sut.collectedProfiles.Load(profile)
	require.False(t, collected)
}

// TestSyscallsForProfileMergesAllKeys asserts that the syscalls of every key of
// a container end up in its profile.
func TestSyscallsForProfileMergesAllKeys(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, false)

	sut.containerIDToProfileMap.Insert(containerID, profile)
	sut.containerKeys.Insert(1, containerID)
	sut.containerKeys.Insert(2, containerID)

	mock.GetValue64ReturnsOnCall(0, []byte{1, 0, 0}, nil)
	mock.GetValue64ReturnsOnCall(1, []byte{0, 0, 1}, nil)
	mock.GetNameCalls(func(id seccomp.ScmpSyscall) (string, error) {
		return fmt.Sprintf("syscall_%d", id), nil
	})

	resp, err := sut.SyscallsForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.NoError(t, err)
	require.Equal(t, []string{"syscall_0", "syscall_2"}, resp.GetSyscalls())
}

// TestSyscallsForProfileWithoutData asserts that a container which recorded
// nothing is reported as not found instead of failing the collection forever.
func TestSyscallsForProfileWithoutData(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, false)

	sut.containerIDToProfileMap.Insert(containerID, profile)
	sut.containerKeys.Insert(1, containerID)

	mock.GetValue64Returns(nil, syscall.ENOENT)

	_, err := sut.SyscallsForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.ErrorIs(t, err, ErrNotFound)
}

// TestApparmorForProfileWithoutData asserts that no empty profile is handed
// out, which would replace a stored one with a profile that allows nothing.
func TestApparmorForProfileWithoutData(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), false, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	mock.BPFLSMEnabledReturns(true)
	sut.impl = mock

	require.NoError(t, sut.Load())

	_, err := sut.Start(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)

	sut.containerIDToProfileMap.Insert(containerID, profile)
	sut.containerKeys.Insert(1, containerID)

	_, err = sut.ApparmorForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestCheckLostEvents(t *testing.T) {
	t.Parallel()

	logSink := &Logger{}
	sut := New("", logr.New(logSink), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock
	sut.lostEventsBpfMap = &libbpfgo.BPFMap{}

	perCPU := func(values ...uint64) []byte {
		raw := make([]byte, 8*len(values))
		for i, v := range values {
			binary.LittleEndian.PutUint64(raw[8*i:], v)
		}

		return raw
	}

	mock.GetValueCalls(func(_ *libbpfgo.BPFMap, reason uint32) ([]byte, error) {
		if reason == lostRingbuf {
			return perCPU(2, 3), nil
		}

		return perCPU(0, 0), nil
	})

	sut.checkLostEvents()

	require.Equal(t, uint64(5), sut.lostEvents[lostRingbuf])
	require.Contains(t, logSink.snapshot(),
		"WARNING: the BPF ring buffer was full, recorded profiles may be incomplete")
	require.NotContains(t, logSink.snapshot(),
		"WARNING: too many workloads are recorded at once, "+
			"recorded seccomp profiles may be incomplete")
}

func podWithContainer(annotations map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pod,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{{
				ContainerID: crioPrefix + containerID,
				Name:        "ctr",
			}},
		},
	}
}

// watchPods has the recorder watch the pods until the test ends, and waits
// for their initial list. Containers which no pod has are waited for only
// briefly.
func watchPods(t *testing.T, sut *BpfRecorder, pods ...*v1.Pod) *podindextest.ListerWatcher {
	t.Helper()

	items := make([]v1.Pod, 0, len(pods))
	for _, p := range pods {
		items = append(items, *p)
	}

	lw := podindextest.New(items...)

	idx, err := podindex.New(lw)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go idx.Run(ctx)

	require.Eventually(t, idx.HasSynced, time.Minute, time.Millisecond)

	sut.pods = idx
	sut.containerLookupTimeout = 10 * time.Millisecond

	return lw
}

// modifyPod updates the pod and waits for the recorder to see the update.
func modifyPod(t *testing.T, sut *BpfRecorder, lw *podindextest.ListerWatcher, p *v1.Pod) {
	t.Helper()

	changed := sut.pods.Changed()

	lw.Modify(p)

	select {
	case <-changed:
	case <-time.After(time.Minute):
		require.Fail(t, "pod update not seen")
	}
}

// TestNewPidEventForEveryKey asserts that a process reported again under a
// new key adds that key to its container.
func TestNewPidEventForEveryKey(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), false, false)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock
	sut.clientset = &kubernetes.Clientset{}

	mock.ContainerIDForPIDReturns(containerID, nil)
	watchPods(t, sut, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}))

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 1, generation: sut.recordingGeneration.Load()},
	)

	// The same process is reported again after moving to another key.
	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 2, generation: sut.recordingGeneration.Load()},
	)

	require.Equal(t, 2, mock.ContainerIDForPIDCallCount())
	require.Equal(t, []uint64{1, 2}, sut.containerKeys.Keys(containerID))
}

// TestNewPidEventExcludesUnrecordedContainers asserts that the data of
// workloads which are not recorded is dropped and no longer recorded, so that
// it does not fill up the maps.
func TestNewPidEventExcludesUnrecordedContainers(t *testing.T) {
	t.Parallel()

	for _, uniqueKeys := range []bool{true, false} {
		sut := New("", logr.Discard(), true, true)
		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock
		sut.clientset = &kubernetes.Clientset{}
		sut.uniqueKeys = uniqueKeys
		sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

		mock.ContainerIDForPIDReturns(containerID, nil)
		watchPods(t, sut, podWithContainer(nil))

		sut.AppArmor.handleFileEvent(fileEvent(7, flagRead, "/etc/passwd"))

		sut.handleNewPidEvent(
			newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
		)

		require.Zero(t, sut.containerKeys.Size())

		if !uniqueKeys {
			// Mount namespace inode numbers are reused.
			require.Zero(t, mock.UpdateValue64CallCount())
			require.Contains(t, sut.AppArmor.recordedFiles, recordingKey(7))

			continue
		}

		require.Equal(t, 1, mock.UpdateValue64CallCount())

		_, key, _ := mock.UpdateValue64ArgsForCall(0)
		require.Equal(t, uint64(7), key)

		require.Equal(t, 1, mock.DeleteKey64CallCount())
		require.NotContains(t, sut.AppArmor.recordedFiles, recordingKey(7))

		// Events still in flight are dropped.
		sut.AppArmor.handleFileEvent(fileEvent(7, flagRead, "/etc/passwd"))
		require.NotContains(t, sut.AppArmor.recordedFiles, recordingKey(7))
	}
}

// TestNewPidEventExcludesHostProcesses asserts that processes outside of any
// container are not recorded either.
func TestNewPidEventExcludesHostProcesses(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, false)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock
	sut.clientset = &kubernetes.Clientset{}
	sut.uniqueKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	mock.ContainerIDForPIDReturns("", util.ErrContainerIDNotFound)

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Equal(t, 1, mock.UpdateValue64CallCount())
	require.Zero(t, sut.containerKeys.Size())
}

// TestResetProfileOfRestartedContainer asserts that the data of every run of a
// restarted container belongs to its profile.
func TestResetProfileOfRestartedContainer(t *testing.T) {
	t.Parallel()

	sut, mock := newRecordingRecorder(t, true, false)

	sut.containerIDToProfileMap.Insert("first-run", profile)
	sut.containerIDToProfileMap.Insert("second-run", profile)
	sut.containerKeys.Insert(1, "first-run")
	sut.containerKeys.Insert(2, "second-run")

	mock.GetValue64ReturnsOnCall(0, []byte{1, 0}, nil)
	mock.GetValue64ReturnsOnCall(1, []byte{0, 1}, nil)
	mock.GetNameCalls(func(id seccomp.ScmpSyscall) (string, error) {
		return fmt.Sprintf("syscall_%d", id), nil
	})

	resp, err := sut.SyscallsForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.NoError(t, err)
	require.Equal(t, []string{"syscall_0", "syscall_1"}, resp.GetSyscalls())

	_, err = sut.ResetSyscallsForProfile(t.Context(), &api.ProfileRequest{Name: profile})
	require.NoError(t, err)
	require.Equal(t, 2, mock.DeleteKey64CallCount())
	require.Zero(t, sut.containerKeys.Size())
}

// TestExcludeKeyAfterSessionEnded asserts that a handler which is still in
// flight when the recording stops does not exclude a key in the next session.
func TestExcludeKeyAfterSessionEnded(t *testing.T) {
	t.Parallel()

	sut := New("", logr.Discard(), true, true)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock
	sut.uniqueKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	generation := sut.recordingGeneration.Load()

	require.NoError(t, sut.StopRecording())

	sut.excludeKey(7, generation)
	require.Zero(t, mock.UpdateValue64CallCount())

	sut.excludeKey(7, sut.recordingGeneration.Load())
	require.Equal(t, 1, mock.UpdateValue64CallCount())
}
