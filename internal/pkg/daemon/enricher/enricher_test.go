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

package enricher

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

const (
	node        = "test-node"
	namespace   = "test-namespace"
	pod         = "test-pod"
	executable  = "/bin/busybox"
	syscall     = "mprotect"
	crioPrefix  = "cri-o://"
	containerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		runAsync bool
		prepare  func(*enricherfakes.FakeImpl, chan *types.AuditLine)
		assert   func(*enricherfakes.FakeImpl, chan *types.AuditLine, error)
	}{
		{ // success
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, nil)
				mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pod,
						Namespace: namespace,
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefix + containerID,
						}},
					},
				}}}, nil)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				for mock.StartTailCallCount() != 1 {
					// Wait for StartTail() to be called
				}

				lineChan <- &types.AuditLine{
					AuditType:    types.AuditTypeSeccomp,
					Executable:   executable,
					SystemCallID: 10,
				}

				for mock.SendMetricCallCount() != 1 {
					// Wait for MetricsAuditIncCallCount to be called
				}

				_, res := mock.SendMetricArgsForCall(0)
				require.Equal(t, node, res.GetNode())
				require.Equal(t, namespace, res.GetNamespace())
				require.Equal(t, pod, res.GetPod())
				require.Equal(t, executable, res.GetExecutable())
				require.NotNil(t, res.GetSeccompReq())
				require.Equal(t, syscall, res.GetSeccompReq().GetSyscall())

				require.Equal(t, 0, mock.AddToBacklogCallCount())

				require.NoError(t, err)
			},
		},

		{ // failure on Getenv
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns("")
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on Dial
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on MetricsAuditInc
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.AuditIncReturns(nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on Tail
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.StartTailReturns(nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},
		{ // failure on Listen
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on Chown
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.ChownReturns(errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},
		{ // failure on log iteration
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				close(lineChan)
				mock.StartTailReturns(lineChan, nil)
				mock.TailErrReturns(errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},
		{ // success, but metrics send failed
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, nil)
				mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pod,
						Namespace: namespace,
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefix + containerID,
						}},
					},
				}}}, nil)
				mock.SendMetricReturns(errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				for mock.StartTailCallCount() != 1 {
					// Wait for StartTail() to be called
				}

				lineChan <- &types.AuditLine{
					AuditType: types.AuditTypeSeccomp,
				}

				for mock.SendMetricCallCount() != 1 {
					// Wait for MetricsAuditIncCallCount to be called
				}

				require.NoError(t, err)
			},
		},
		{ // success, but using the backlog
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.GetenvReturns(node)
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, nil)

				// container.go says that there are 10 retries to get the container
				// ID. Simulate a failure by returning the container ID on the 11th
				// retry
				i := 0
				for ; i < 10; i++ {
					mock.ListPodsReturnsOnCall(i, &v1.PodList{Items: []v1.Pod{{
						ObjectMeta: metav1.ObjectMeta{
							Name:      pod,
							Namespace: namespace,
						},
						Status: v1.PodStatus{
							ContainerStatuses: []v1.ContainerStatus{{
								ContainerID: "",
								State: v1.ContainerState{
									Waiting: &v1.ContainerStateWaiting{
										Reason: "ContainerCreating",
									},
								},
							}},
						},
					}}}, nil)
				}
				mock.ListPodsReturnsOnCall(i, &v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      pod,
						Namespace: namespace,
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefix + containerID,
						}},
					},
				}}}, nil)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				for mock.StartTailCallCount() != 1 {
					// Wait for StartTail() to be called. We should hit continue
					// in the loop, failing the find the container ID
				}

				avcLine := &types.AuditLine{
					AuditType:    types.AuditTypeSelinux,
					TimestampID:  "1613173578.156:2945",
					SystemCallID: 0,
					ProcessID:    75593,
					Executable:   "",
					Perm:         "read",
					Scontext:     "system_u:system_r:container_t:s0:c4,c808",
					Tcontext:     "system_u:object_r:var_lib_t:s0",
					Tclass:       "lnk_file",
				}

				lineChan <- avcLine

				for mock.AddToBacklogCallCount() != 1 {
					// Make sure the backlog was added to, because the
					// pod information shouldn't be available yet
				}
				// nothing should be read from the backlog yet
				require.Equal(t, 0, mock.GetFromBacklogCallCount())

				lineChan <- &types.AuditLine{
					AuditType: types.AuditTypeSeccomp,
				}

				// add something to the mock backlog
				mock.GetFromBacklogReturns([]*types.AuditLine{avcLine})

				// the other line shouldn't hit the backlog, so there
				// should be still only one write to backlog
				require.Equal(t, 1, mock.AddToBacklogCallCount())

				for mock.GetFromBacklogCallCount() != 1 {
					// Make sure the backlog was read from when the avcs
					// were dispatched
				}

				for mock.FlushBacklogCallCount() != 1 {
					// Make sure the backlog was flushed. This ensures
					// that it was not empty and the mock entry was
					// actually processed
				}

				for mock.SendMetricCallCount() != 2 {
				}
				_, firstSysCall := mock.SendMetricArgsForCall(0)
				require.NotNil(t, firstSysCall.GetSelinuxReq())
				_, secondSysCall := mock.SendMetricArgsForCall(1)
				require.NotNil(t, secondSysCall.GetSeccompReq())

				require.NoError(t, err)
			},
		},
	} {
		lineChan := make(chan *types.AuditLine)
		mock := &enricherfakes.FakeImpl{}
		tc.prepare(mock, lineChan)

		sut, errCreate := New(logr.Discard(), nil)
		require.NoError(t, errCreate)

		sut.impl = mock

		var err error

		if tc.runAsync {
			go func() { err = sut.Run() }()
		} else {
			err = sut.Run()
		}

		tc.assert(mock, lineChan, err)
	}
}
