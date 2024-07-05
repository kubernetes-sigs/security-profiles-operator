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
	"time"

	"github.com/go-logr/logr"
	"github.com/nxadm/tail"
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
	seccompLine = `type=SECCOMP msg=audit(1624537480.360:8477): auid=1000 ` +
		`uid=0 gid=0 ses=1 subj=kernel pid=2060394 comm="sleep" ` +
		`exe="` + executable + `" sig=0 arch=c000003e syscall=10 compat=0 ` +
		`ip=0x7f4ce626349b code=0x7ffc0000 AUID="user" UID="root" ` +
		`GID="root" ARCH=x86_64 SYSCALL=` + syscall
	avcLine = `type=AVC msg=audit(1613173578.156:2945): avc:  denied ` +
		`{ read } for  pid=75593 comm="security-profil" name="token" ` +
		`dev="tmpfs" ino=612459 ` +
		`scontext=system_u:system_r:container_t:s0:c4,c808 ` +
		`tcontext=system_u:object_r:var_lib_t:s0 tclass=lnk_file permissive=0`
	containerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		runAsync bool
		prepare  func(*enricherfakes.FakeImpl, chan *tail.Line)
		assert   func(*enricherfakes.FakeImpl, chan *tail.Line, error)
	}{
		{ // success
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.LinesReturns(lineChan)
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
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				for mock.LinesCallCount() != 1 {
					// Wait for Lines() to be called
				}

				lineChan <- &tail.Line{
					Text: seccompLine,
					Time: time.Now(),
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

				require.Nil(t, err)
			},
		},
		{ // failure on Getenv
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns("")
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // failure on Dial
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // failure on MetricsAuditInc
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.AuditIncReturns(nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // failure on Tail
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.TailFileReturns(nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // failure on Listen
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // failure on Chown
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				mock.ChownReturns(errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // failure on Lines
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.DialReturns(nil, func() {}, errTest)
				close(lineChan)
				mock.LinesReturns(lineChan)
				mock.ReasonReturns(errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
			},
		},
		{ // success, but metrics send failed
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.LinesReturns(lineChan)
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
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				for mock.LinesCallCount() != 1 {
					// Wait for Lines() to be called
				}

				lineChan <- &tail.Line{
					Text: seccompLine,
					Time: time.Now(),
				}

				for mock.SendMetricCallCount() != 1 {
					// Wait for MetricsAuditIncCallCount to be called
				}

				require.Nil(t, err)
			},
		},
		{ // success, but using the backlog
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(node)
				mock.LinesReturns(lineChan)
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
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				for mock.LinesCallCount() != 1 {
					// Wait for Lines() to be called. We should hit continue
					// in the loop, failing the find the container ID
				}

				lineChan <- &tail.Line{
					Text: avcLine,
					Time: time.Now(),
				}

				for mock.AddToBacklogCallCount() != 1 {
					// Make sure the backlog was added to, because the
					// pod information shouldn't be available yet
				}
				// nothing should be read from the backlog yet
				require.Equal(t, mock.GetFromBacklogCallCount(), 0)

				lineChan <- &tail.Line{
					Text: avcLine,
					Time: time.Now(),
				}

				// the other line shouldn't hit the backlog, so there
				// should be still only one write to backlog
				require.Equal(t, mock.AddToBacklogCallCount(), 1)

				// add something to the mock backlog
				mock.GetFromBacklogReturns(
					[]*types.AuditLine{
						{
							AuditType:    "selinux",
							TimestampID:  "1613173578.156:2945",
							SystemCallID: 0,
							ProcessID:    75593,
							Executable:   "",
							Perm:         "read",
							Scontext:     "system_u:system_r:container_t:s0:c4,c808",
							Tcontext:     "system_u:object_r:var_lib_t:s0",
							Tclass:       "lnk_file",
						},
					},
				)

				for mock.GetFromBacklogCallCount() != 1 {
					// Make sure the backlog was read from when the avcs
					// were dispatched
				}

				for mock.FlushBacklogCallCount() != 1 {
					// Make sure the backlog was flushed. This ensures
					// that it was not empty and the mock entry was
					// actually processed
				}
				require.Nil(t, err)
			},
		},
	} {
		lineChan := make(chan *tail.Line)
		mock := &enricherfakes.FakeImpl{}
		tc.prepare(mock, lineChan)

		sut := New(logr.Discard())
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
