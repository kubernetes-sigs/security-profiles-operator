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
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/nxadm/tail"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
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
	containerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
	cgroupLine  = "0::/kubepods/burstable/" +
		"pod4baee654-1da5-4d8c-a110-864a22f9ae39/" +
		"crio-" + containerID + "\n"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp("", "cgroup-")
	require.Nil(t, err)
	_, err = f.WriteString(cgroupLine)
	require.Nil(t, err)
	require.Nil(t, f.Close())
	cgroupFilePath := f.Name()
	defer os.Remove(cgroupFilePath)

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
				mock.OpenCalls(func(string) (*os.File, error) {
					return os.Open(cgroupFilePath)
				})
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
				require.Equal(t, node, res.Node)
				require.Equal(t, namespace, res.Namespace)
				require.Equal(t, pod, res.Pod)
				require.Equal(t, executable, res.Executable)
				require.Equal(t, syscall, res.Syscall)

				require.Nil(t, err)
			},
		},
		{ // failure on SetTTL
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.SetTTLReturns(errTest)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err error) {
				require.NotNil(t, err)
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
				mock.MetricsAuditIncReturns(nil, errTest)
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
				mock.OpenCalls(func(string) (*os.File, error) {
					return os.Open(cgroupFilePath)
				})
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
	} {
		lineChan := make(chan *tail.Line)
		mock := &enricherfakes.FakeImpl{}
		tc.prepare(mock, lineChan)

		sut := New(logr.DiscardLogger{})
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
