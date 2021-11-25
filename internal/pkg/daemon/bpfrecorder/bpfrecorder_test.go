//go:build linux
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
	"context"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
		{ // SetTTL fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.SetTTLReturns(errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
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
				mock.AtoiReturns(0, errTest)
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
		{ // load:AttachTracepoint fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.AttachTracepointReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetMap fails on first call
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetMapReturns(nil, errTest)
			},
			assert: func(err error) {
				require.NotNil(t, err)
			},
		},
		{ // load:GetMap fails on second call
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns(node)
				mock.GoArchReturns(validGoArch)
				mock.GetMapReturnsOnCall(1, nil, errTest)
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
				mock.TempFileCalls(ioutil.TempFile)
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

		sut := New(logr.DiscardLogger{})
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

		sut := New(logr.DiscardLogger{})
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
		sut := New(logr.DiscardLogger{})

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
				sut.pidsForProfiles.Store(profile, []Pid{
					{id: 42, comm: "sh", mntns: 1337},
					{id: 43, comm: "bash", mntns: 1338},
				})
				mock.GetValueReturns([]byte{0, 0, 0, 1, 1, 1}, nil)
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
				sut.pidsForProfiles.Store(profile, []Pid{
					{id: 42, comm: "sh", mntns: 1337},
					{id: 43, comm: "bash", mntns: 1338},
				})
				mock.GetValueReturns([]byte{0, 1, 1}, nil)
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
		{ // result not a PID type
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.pidsForProfiles.Store(profile, "wrong")
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // PID slice empty
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.pidsForProfiles.Store(profile, []Pid{})
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.NotNil(t, err)
			},
		},
		{ // no syscall found for PID
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) {
				mock.GoArchReturns(validGoArch)
				_, err := sut.Start(context.Background(), &api.EmptyRequest{})
				require.Nil(t, err)
				sut.pidsForProfiles.Store(profile, []Pid{
					{id: 42, comm: "sh", mntns: 1337},
				})
				mock.GetValueReturns(nil, errTest)
			},
			assert: func(sut *BpfRecorder, resp *api.SyscallsResponse, err error) {
				require.Nil(t, err)
			},
		},
	} {
		sut := New(logr.DiscardLogger{})

		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		tc.prepare(sut, mock)

		resp, err := sut.SyscallsForProfile(
			context.Background(), &api.ProfileRequest{Name: profile},
		)
		tc.assert(sut, resp, err)
	}
}

type Logger struct {
	messages []string
	mutex    sync.RWMutex
}

func (l *Logger) Enabled() bool                                       { return true }
func (l *Logger) V(level int) logr.Logger                             { return l }
func (l *Logger) WithValues(keysAndValues ...interface{}) logr.Logger { return l }
func (l *Logger) WithName(name string) logr.Logger                    { return l }

func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.mutex.Lock()
	l.messages = append(l.messages, msg)
	l.mutex.Unlock()
}

func (l *Logger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.mutex.Lock()
	l.messages = append(l.messages, msg)
	l.mutex.Unlock()
}

func TestProcessEvents(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*BpfRecorder, *bpfrecorderfakes.FakeImpl) (msg []byte)
		assert  func(*BpfRecorder, *Logger)
	}{
		{ // Success
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) []byte {
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
				return []byte{
					1, 0, 0, 0, 0, 0, 0, 0,
					1, 0, 0, 0, 0, 0, 0, 0,
				}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				mntns := binary.LittleEndian.Uint64([]byte{1, 0, 0, 0, 0, 0, 0, 0})
				var (
					ok      bool
					profile interface{}
				)
				for i := 0; i < 100; i++ {
					profile, ok = sut.profileForMountNamespace.Load(mntns)
					if ok {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				require.Equal(t, "profile.json", profile)
			},
		},
		{ // Success short path
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) []byte {
				mntns := binary.LittleEndian.Uint64([]byte{1, 0, 0, 0, 0, 0, 0, 0})
				sut.profileForMountNamespace.Store(mntns, "profile.json")
				return []byte{
					1, 0, 0, 0, 0, 0, 0, 0,
					1, 0, 0, 0, 0, 0, 0, 0,
				}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				success := false
				for i := 0; i < 100; i++ {
					logger.mutex.RLock()
					success = util.Contains(logger.messages, "Using short path via tracked mount namespace")
					logger.mutex.RUnlock()
					if success {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				require.True(t, success)
			},
		},
		{ // invalid event length
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) []byte {
				return []byte{1, 0, 0}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				success := false
				for i := 0; i < 100; i++ {
					logger.mutex.RLock()
					success = util.Contains(logger.messages, "Invalid event length")
					logger.mutex.RUnlock()
					if success {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				require.True(t, success)
			},
		},
		{ // unable to find container ID
			prepare: func(sut *BpfRecorder, mock *bpfrecorderfakes.FakeImpl) []byte {
				mock.ContainerIDForPIDReturns(containerID, nil)
				mock.ListPodsReturns(nil, errTest)
				return []byte{
					1, 0, 0, 0, 0, 0, 0, 0,
					1, 0, 0, 0, 0, 0, 0, 0,
				}
			},
			assert: func(sut *BpfRecorder, logger *Logger) {
				success := false
				for i := 0; i < 100; i++ {
					logger.mutex.RLock()
					success = util.Contains(logger.messages, "unable to find container ID in cluster")
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
		logger := &Logger{}
		sut := New(logger)
		mock := &bpfrecorderfakes.FakeImpl{}
		sut.impl = mock

		msg := tc.prepare(sut, mock)

		ch := make(chan []byte)
		go sut.processEvents(ch)
		ch <- msg

		tc.assert(sut, logger)
		close(ch)
	}
}
