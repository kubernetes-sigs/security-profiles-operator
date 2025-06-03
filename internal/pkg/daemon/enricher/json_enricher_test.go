/*
Copyright 2025 The Kubernetes Authors.

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
	"context"
	"encoding/json"
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
	nodeJsonTest         = "test-node"
	namespaceJsonTest    = "test-namespace"
	podJsonTest          = "test-pod"
	executableBusybox    = "/bin/busybox"
	executableNginx      = "/bin/nginx"
	syscallJsonTest      = "mprotect"
	crioPrefixJsonTest   = "cri-o://"
	seccompLineJsonTest1 = `type=SECCOMP msg=audit(1624537480.360:8477): auid=1000 ` +
		`uid=0 gid=0 ses=1 subj=kernel pid=2060394 comm="sleep" ` +
		`exe="` + executableBusybox + `" sig=0 arch=c000003e syscall=10 compat=0 ` +
		`ip=0x7f4ce626349b code=0x7ffc0000 AUID="user" UID="root" ` +
		`GID="root" ARCH=x86_64 SYSCALL=` + executableBusybox
	seccompLineJsonTest2 = `type=SECCOMP msg=audit(1624537480.360:8477): auid=1000 ` +
		`uid=0 gid=0 ses=1 subj=kernel pid=2060395 comm="sleep" ` +
		`exe="` + executableNginx + `" sig=0 arch=c000003e syscall=10 compat=0 ` +
		`ip=0x7f4ce626349b code=0x7ffc0000 AUID="user" UID="root" ` +
		`GID="root" ARCH=x86_64 SYSCALL=` + executableNginx
	containerIDJsonTest      = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
	cmdLineJsonTest          = "/bin/sh "
	invalidLineJsonTest      = "this line is not a valid line for the parser"
	auditLogFlushTimeSeconds = 5
)

func TestJsonRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		runAsync bool
		prepare  func(*enricherfakes.FakeImpl, chan *tail.Line)
		assert   func(*enricherfakes.FakeImpl, chan *tail.Line, chan error)
	}{
		{ // test a basic case of sending the log
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(nodeJsonTest)
				mock.LinesReturns(lineChan)
				mock.ContainerIDForPIDReturns(containerIDJsonTest, nil)
				mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podJsonTest,
						Namespace: namespaceJsonTest,
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefixJsonTest + containerIDJsonTest,
						}},
					},
				}}}, nil)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err chan error) {
				for mock.LinesCallCount() != 1 {
					// Wait for Lines() to be called
				}

				// Ensure that time to get the log is around the time the
				startTime := time.Now()

				lineChan <- &tail.Line{
					Text: seccompLineJsonTest1,
					Time: time.Now(),
				}

				for mock.PrintJsonOutputCallCount() != 1 {
					// Wait for PrintJsonOutputCallCount() to be called
				}

				endTime := time.Now()
				executionTime := endTime.Sub(startTime)

				// Ensure that its not less than flush time
				require.Less(t, float64(auditLogFlushTimeSeconds), executionTime.Seconds())

				// Ensure that its not very long after the flush time
				require.Less(t, executionTime.Seconds(), float64(auditLogFlushTimeSeconds*2))

				auditMap := make(map[string]interface{})
				_, output := mock.PrintJsonOutputArgsForCall(0)
				errUnmarshal := json.Unmarshal([]byte(output), &auditMap)
				require.NoError(t, errUnmarshal)
				executable := auditMap["executable"]
				require.Equal(t, executableBusybox, executable)
			},
		},
		{ // test multiple lines
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(nodeJsonTest)
				mock.LinesReturns(lineChan)
				mock.ContainerIDForPIDReturns(containerIDJsonTest, nil)
				mock.CmdlineForPIDReturns(cmdLineJsonTest, nil)
				mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podJsonTest,
						Namespace: namespaceJsonTest,
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefixJsonTest + containerIDJsonTest,
						}},
					},
				}}}, nil)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err chan error) {
				for mock.LinesCallCount() != 1 {
					// Wait for Lines() to be called
				}

				lineChan <- &tail.Line{
					Text: seccompLineJsonTest1,
					Time: time.Now(),
				}

				for mock.PrintJsonOutputCallCount() != 1 {
					// Wait for PrintJsonOutputCallCount() to be called
				}

				lineChan <- &tail.Line{
					Text: seccompLineJsonTest2,
					Time: time.Now(),
				}

				for mock.PrintJsonOutputCallCount() != 2 {
					// Wait for PrintJsonOutputCallCount() to be called
				}

				auditMap := make(map[string]interface{})
				_, output := mock.PrintJsonOutputArgsForCall(0)
				errUnmarshal := json.Unmarshal([]byte(output), &auditMap)
				require.NoError(t, errUnmarshal)
				executable := auditMap["executable"]
				require.Equal(t, executableBusybox, executable)

				_, output = mock.PrintJsonOutputArgsForCall(1)
				errUnmarshal = json.Unmarshal([]byte(output), &auditMap)
				require.NoError(t, errUnmarshal)
				executable = auditMap["executable"]
				require.Equal(t, executableNginx, executable)
				//nolint:all
				require.Equal(t, cmdLineJsonTest, auditMap["cmdLine"])
			},
		},
		{ // test invalid
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
				mock.GetenvReturns(nodeJsonTest)
				mock.LinesReturns(lineChan)
				mock.ContainerIDForPIDReturns(containerIDJsonTest, nil)
				mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podJsonTest,
						Namespace: namespaceJsonTest,
					},
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{{
							ContainerID: crioPrefixJsonTest + containerIDJsonTest,
						}},
					},
				}}}, nil)
			},
			assert: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line, err chan error) {
				for mock.LinesCallCount() != 1 {
					// Wait for Lines() to be called
				}

				lineChan <- &tail.Line{
					Text: invalidLineJsonTest,
					Time: time.Now(),
				}
			},
		},
	} {
		lineChan := make(chan *tail.Line)
		mock := &enricherfakes.FakeImpl{}
		tc.prepare(mock, lineChan)

		jsonEnricherOpts := &JsonEnricherOptions{}
		jsonEnricherOpts.AuditFreq = time.Duration(auditLogFlushTimeSeconds) * time.Second
		sut, jsonEnricherErr := NewJsonEnricherArgs(logr.Discard(), jsonEnricherOpts)
		require.NoError(t, jsonEnricherErr)

		sut.impl = mock

		var err chan error

		if tc.runAsync {
			go func() { sut.Run(context.Background(), err) }()
		} else {
			sut.Run(context.Background(), err)
		}

		tc.assert(mock, lineChan, err)
	}
}
