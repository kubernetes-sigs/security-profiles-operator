//go:build linux

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

package enricher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	node       = "test-node"
	namespace  = "test-namespace"
	pod        = "test-pod"
	executable = "/bin/busybox"
	crioPrefix = "cri-o://"

	otherContainerID = "e1d4c1dbd3b5d9a4e9e2f6f5a1c8f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"
)

var errTest = errors.New("test")

// fakeListener is a listener which only tells whether it got closed.
type fakeListener struct {
	net.Listener

	closed atomic.Bool
}

func (l *fakeListener) Close() error {
	l.closed.Store(true)

	return nil
}

// startRun runs the enricher in the background and returns the channel which
// gets its outcome.
func startRun(t *testing.T, sut *Enricher) chan error {
	t.Helper()

	runErr := make(chan error, 1)

	go func() { runErr <- sut.Run(t.Context()) }()

	return runErr
}

// stopRun ends the audit log, which makes Run return, and asserts that it
// returned because of that rather than an earlier failure.
func stopRun(t *testing.T, lineChan chan *types.AuditLine, runErr chan error) {
	t.Helper()

	close(lineChan)

	select {
	case err := <-runErr:
		require.ErrorContains(t, err, "enricher failed")
	case <-time.After(time.Minute):
		t.Fatal("Run did not return")
	}
}

// waitForCallCount waits until want calls have been recorded, failing the test
// rather than hanging until the package timeout if that never happens.
func waitForCallCount(t *testing.T, count func() int, want int) {
	t.Helper()

	require.Eventually(t, func() bool { return count() == want }, time.Minute, time.Millisecond,
		"expected %d calls", want)
}

func TestRun(t *testing.T) {
	t.Parallel()

	backlogPods := podindextest.New(*creatingPod())

	for _, tc := range []struct {
		name    string
		prepare func(*enricherfakes.FakeImpl, chan *types.AuditLine)
		assert  func(*testing.T, *Enricher, *enricherfakes.FakeImpl, chan *types.AuditLine, chan error)
	}{
		{
			name: "success",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, 0, nil)
				mock.PodListerWatcherReturns(podindextest.New(*runningPod()))
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				waitForCallCount(t, mock.StartTailCallCount, 1)

				lineChan <- &types.AuditLine{
					AuditType:    types.AuditTypeSeccomp,
					Executable:   executable,
					SystemCallID: 10,
				}

				waitForCallCount(t, mock.SendMetricCallCount, 1)

				// The syscall numbers differ between the architectures.
				wantSyscall, nameErr := syscallName(10, "")
				require.NoError(t, nameErr)

				_, res := mock.SendMetricArgsForCall(0)
				require.Equal(t, node, res.GetNode())
				require.Equal(t, namespace, res.GetNamespace())
				require.Equal(t, pod, res.GetPod())
				require.Equal(t, executable, res.GetExecutable())
				require.NotNil(t, res.GetSeccompReq())
				require.Equal(t, wantSyscall, res.GetSeccompReq().GetSyscall())

				require.Zero(t, sut.auditLineCache.Len())

				stopRun(t, lineChan, runErr)
			},
		},

		{
			name: "failure on Dial",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.Error(t, <-runErr)
			},
		},

		{
			name: "failure on MetricsAuditInc",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.AuditIncReturns(nil, errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.Error(t, <-runErr)
			},
		},

		{
			name: "failure on Tail",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.StartTailReturns(nil, errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.Error(t, <-runErr)
			},
		},
		{
			name: "failure on Listen",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.Error(t, <-runErr)
			},
		},

		{
			name: "failure on Chown",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.ChownReturns(errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.Error(t, <-runErr)
			},
		},
		{
			name: "failure on log iteration",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				close(lineChan)
				mock.StartTailReturns(lineChan, nil)
				mock.PodListerWatcherReturns(podindextest.New())
				mock.TailErrReturns(errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.ErrorIs(t, <-runErr, errTest)
			},
		},
		{
			name: "log ends without error",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				close(lineChan)
				mock.StartTailReturns(lineChan, nil)
				mock.PodListerWatcherReturns(podindextest.New())
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				require.ErrorIs(t, <-runErr, errTailEnded)
			},
		},
		{
			name: "success, but metrics send failed",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, 0, nil)
				mock.PodListerWatcherReturns(podindextest.New(*runningPod()))
				mock.SendMetricReturns(errTest)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				waitForCallCount(t, mock.StartTailCallCount, 1)

				lineChan <- &types.AuditLine{
					AuditType: types.AuditTypeSeccomp,
				}

				waitForCallCount(t, mock.SendMetricCallCount, 1)

				stopRun(t, lineChan, runErr)
			},
		},
		{
			name: "success, but using the backlog",
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, 0, nil)
				mock.PodListerWatcherReturns(backlogPods)
			},
			assert: func(
				t *testing.T, sut *Enricher, mock *enricherfakes.FakeImpl,
				lineChan chan *types.AuditLine, runErr chan error,
			) {
				t.Helper()

				waitForCallCount(t, mock.StartTailCallCount, 1)

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

				// The pod does not tell the container yet.
				waitForCallCount(t, sut.auditLineCache.Len, 1)
				require.Zero(t, mock.SendMetricCallCount())

				// The update of the pod sends the backlog, without another
				// line of the container.
				backlogPods.Modify(runningPod())

				waitForCallCount(t, sut.auditLineCache.Len, 0)
				waitForCallCount(t, mock.SendMetricCallCount, 1)

				lineChan <- &types.AuditLine{
					AuditType: types.AuditTypeSeccomp,
					ProcessID: avcLine.ProcessID,
				}

				waitForCallCount(t, mock.SendMetricCallCount, 2)

				_, firstSysCall := mock.SendMetricArgsForCall(0)
				require.NotNil(t, firstSysCall.GetSelinuxReq())

				_, secondSysCall := mock.SendMetricArgsForCall(1)
				require.NotNil(t, secondSysCall.GetSeccompReq())

				stopRun(t, lineChan, runErr)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lineChan := make(chan *types.AuditLine)
			mock := &enricherfakes.FakeImpl{}
			mock.PodListerWatcherReturns(podindextest.New())
			mock.ListenReturns(&fakeListener{}, nil)
			tc.prepare(mock, lineChan)

			sut, errCreate := New(logr.Discard(), nil)
			require.NoError(t, errCreate)

			sut.impl = mock
			sut.nodeName = node
			// Do not spend the production backoff as test wall-clock time.
			sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

			// Run only returns when the audit log ends, so the async cases
			// assert on the side effects and end the log afterwards.
			tc.assert(t, sut, mock, lineChan, startRun(t, sut))
		})
	}
}

func TestRunWithoutNodeName(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = &enricherfakes.FakeImpl{}
	sut.nodeName = ""

	require.Error(t, sut.Run(t.Context()))
}

// TestRunDropsLinesWithoutContainer asserts that lines of host processes and of
// processes which are gone are not kept around: a later line with the same
// PID may come from another process which reused it.
func TestRunDropsLinesWithoutContainer(t *testing.T) {
	t.Parallel()

	for name, lookupErr := range map[string]error{
		"host process":   util.ErrContainerIDNotFound,
		"exited process": os.ErrNotExist,
		"exited process while reading its files": fmt.Errorf(
			"reading proc start time: %w", syscall.ESRCH,
		),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			lineChan := make(chan *types.AuditLine)
			mock := &enricherfakes.FakeImpl{}
			mock.StartTailReturns(lineChan, nil)
			mock.ContainerIDForPIDReturnsOnCall(0, "", 0, lookupErr)
			mock.ContainerIDForPIDReturnsOnCall(1, containerID, 0, nil)
			mock.PodListerWatcherReturns(podindextest.New(*runningPod()))

			sut, err := New(logr.Discard(), nil)
			require.NoError(t, err)

			sut.impl = mock
			sut.nodeName = node
			sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

			runErr := startRun(t, sut)

			lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 42}

			waitForCallCount(t, mock.ContainerIDForPIDCallCount, 1)
			require.Zero(t, sut.auditLineCache.Len())

			// The process reusing the PID gets only its own line.
			lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 42}

			waitForCallCount(t, mock.SendMetricCallCount, 1)
			require.Zero(t, sut.auditLineCache.Len())

			stopRun(t, lineChan, runErr)
		})
	}
}

// TestRunAttributesLinesOfExitedProcess asserts that the lines of a process
// read after it exited go to the container it had while it was running, which
// is all that is left of short lived processes like init containers.
func TestRunAttributesLinesOfExitedProcess(t *testing.T) {
	t.Parallel()

	const recordProfile = "profile"

	lineChan := make(chan *types.AuditLine)
	mock := &enricherfakes.FakeImpl{}
	mock.StartTailReturns(lineChan, nil)
	mock.ContainerIDForPIDReturnsOnCall(0, containerID, 0, nil)
	mock.ContainerIDForPIDReturns("", 0, os.ErrNotExist)
	mock.PodListerWatcherReturns(podindextest.New(v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod,
			Namespace: namespace,
			Annotations: map[string]string{
				config.SeccompProfileRecordLogsAnnotationKey + "init": recordProfile,
			},
		},
		Status: v1.PodStatus{
			InitContainerStatuses: []v1.ContainerStatus{{
				Name:        "init",
				ContainerID: crioPrefix + containerID,
			}},
		},
	}))

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

	runErr := startRun(t, sut)

	syscalls := []int32{0, 1, 2}
	names := make([]string, 0, len(syscalls))

	for _, syscall := range syscalls {
		name, err := syscallName(syscall, "")
		require.NoError(t, err)

		names = append(names, name)

		lineChan <- &types.AuditLine{
			AuditType: types.AuditTypeSeccomp, ProcessID: 42, SystemCallID: syscall,
		}
	}

	// A line of another process which is gone without having been seen.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 43}

	waitForCallCount(t, mock.ContainerIDForPIDCallCount, 4)
	waitForCallCount(t, mock.SendMetricCallCount, 3)

	recorded, found := sut.syscalls.get(recordProfile, false)
	require.True(t, found)
	require.ElementsMatch(t, names, recorded)

	stopRun(t, lineChan, runErr)
}

// TestContainerIDForProcessForgetsReusedPID asserts that the container of an
// exited process is not used any more once a process outside of a container
// runs with its PID.
func TestContainerIDForProcessForgetsReusedPID(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	mock.ContainerIDForPIDReturnsOnCall(0, containerID, 0, nil)
	mock.ContainerIDForPIDReturnsOnCall(1, "", 0, util.ErrContainerIDNotFound)
	mock.ContainerIDForPIDReturnsOnCall(2, "", 0, os.ErrNotExist)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock

	cID, err := sut.lookup.containerIDForProcess(sut.impl, 42, time.Time{})
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	_, err = sut.lookup.containerIDForProcess(sut.impl, 42, time.Time{})
	require.ErrorIs(t, err, util.ErrContainerIDNotFound)

	_, err = sut.lookup.containerIDForProcess(sut.impl, 42, time.Time{})
	require.ErrorIs(t, err, os.ErrNotExist)
}

// TestContainerIDForProcessWithESRCH asserts that a process which exits while
// its files get read counts as gone, and gets the container it was last seen
// running in.
func TestContainerIDForProcessWithESRCH(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	mock.ContainerIDForPIDReturnsOnCall(0, containerID, 0, nil)
	mock.ContainerIDForPIDReturnsOnCall(1, "", 0, fmt.Errorf("read stat: %w", syscall.ESRCH))

	lookup := newContainerLookup(logr.Discard())

	cID, err := lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	cID, err = lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)
	require.Equal(t, containerID, cID)
}

// TestContainerIDForProcessChecksStartTime asserts that the line of a process
// is not attributed to a process which reused its PID after the line got
// logged.
func TestContainerIDForProcessChecksStartTime(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	// The process with the PID started ten seconds ago.
	mock.ContainerIDForPIDReturns(containerID, time.Hour-10*time.Second, nil)
	mock.UptimeReturns(time.Hour, nil)

	lookup := newContainerLookup(logr.Discard())

	_, err := lookup.containerIDForProcess(mock, 42, time.Now().Add(-time.Minute))
	require.ErrorIs(t, err, errProcessStartedLater)
	require.Nil(t, lookup.processContainers.Get(42))

	cID, err := lookup.containerIDForProcess(mock, 42, time.Now())
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	// The start time comes with the container, the stat file of the process
	// is not read again.
	require.Zero(t, mock.ProcessStartTimeCallCount())

	// Without the time of the line, the check is skipped.
	cID, err = lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	// As it is without the time since boot.
	mock.UptimeReturns(0, errors.New("no boot time"))

	cID, err = lookup.containerIDForProcess(mock, 42, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	// A process which exited after its container got looked up gets the
	// container it was last seen running in.
	mock.ContainerIDForPIDReturns("", 0, os.ErrNotExist)

	cID, err = lookup.containerIDForProcess(mock, 42, time.Now())
	require.NoError(t, err)
	require.Equal(t, containerID, cID)
}

// TestContainerIDForProcessClockSteps asserts that a step of the wall clock
// while lines wait does not drop the lines of a process, while a reused PID
// is still detected.
func TestContainerIDForProcessClockSteps(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	// The process with the PID started ten seconds ago.
	mock.ContainerIDForPIDReturns(containerID, time.Hour-10*time.Second, nil)
	mock.UptimeReturns(time.Hour, nil)

	lookup := newContainerLookup(logr.Discard())

	// The line got logged five seconds ago, before the wall clock got
	// stepped forward by 30 seconds: the boot seems to be 30 seconds later
	// now, and the process to have started 20 seconds in the future.
	logged := time.Now().Add(-5 * time.Second)

	_, err := lookup.containerIDForProcess(mock, 42, logged)
	require.NoError(t, err)

	mock.UptimeReturns(time.Hour-30*time.Second, nil)

	cID, err := lookup.containerIDForProcess(mock, 42, logged)
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	// A line logged before the process started is still dropped.
	_, err = lookup.containerIDForProcess(mock, 42, time.Now().Add(-time.Minute))
	require.ErrorIs(t, err, errProcessStartedLater)

	// A backward step makes the boot earlier right away. The process which
	// reused the PID started ten seconds ago in that time.
	mock.UptimeReturns(time.Hour+30*time.Second, nil)
	mock.ContainerIDForPIDReturns(containerID, time.Hour+20*time.Second, nil)

	_, err = lookup.containerIDForProcess(mock, 42, time.Now().Add(-time.Minute))
	require.ErrorIs(t, err, errProcessStartedLater)

	cID, err = lookup.containerIDForProcess(mock, 42, time.Now())
	require.NoError(t, err)
	require.Equal(t, containerID, cID)
}

// TestBootClockWindow asserts that a later boot time gets used once the
// earlier one is older than the window.
func TestBootClockWindow(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	mock.UptimeReturns(time.Hour, nil)

	var sut bootClock

	early, ok := sut.get(mock)
	require.True(t, ok)

	// A forward step by a minute.
	mock.UptimeReturns(time.Hour-time.Minute, nil)

	boot, ok := sut.get(mock)
	require.True(t, ok)
	require.Equal(t, early, boot)

	// The window of the early boot time passed, it is still used during the
	// next one.
	sut.windowStart = sut.windowStart.Add(-bootTimeWindow)

	boot, ok = sut.get(mock)
	require.True(t, ok)
	require.Equal(t, early, boot)

	sut.windowStart = sut.windowStart.Add(-bootTimeWindow)

	boot, ok = sut.get(mock)
	require.True(t, ok)
	require.WithinDuration(t, early.Add(time.Minute), boot, time.Second)

	mock.UptimeReturns(0, nil)

	_, ok = sut.get(mock)
	require.False(t, ok)
}

// TestProcessAuditLineDropsLineOfReusedPID asserts that the line of a process
// whose PID got reused after the line got logged is dropped.
func TestProcessAuditLineDropsLineOfReusedPID(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	mock.ContainerIDForPIDReturns(containerID, time.Hour-10*time.Second, nil)
	mock.UptimeReturns(time.Hour, nil)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock

	logged := time.Now().Add(-time.Minute)
	sut.processAuditLine(node, &types.AuditLine{
		AuditType:   types.AuditTypeSeccomp,
		ProcessID:   42,
		TimestampID: fmt.Sprintf("%d.%03d:1", logged.Unix(), logged.UnixMilli()%1000),
	})

	// Neither kept for its container nor attributed to the container of the
	// process which reused the PID.
	require.Zero(t, sut.auditLineCache.Len())
	require.Nil(t, sut.lookup.processContainers.Get(42))
}

// TestContainerIDForProcessRefreshesRarely asserts that the container of a
// running process is not kept again for each of its lines, while a change of
// the container is kept right away.
func TestContainerIDForProcessRefreshesRarely(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	mock.ContainerIDForPIDReturns(containerID, 0, nil)

	lookup := newContainerLookup(logr.Discard())

	_, err := lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)

	kept := lookup.processContainers.Get(42)
	require.NotNil(t, kept)

	_, err = lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)
	require.Equal(t, kept.ExpiresAt(), lookup.processContainers.Get(42).ExpiresAt())

	mock.ContainerIDForPIDReturns(otherContainerID, 0, nil)

	_, err = lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)
	require.Equal(t, otherContainerID, lookup.processContainers.Get(42).Value())

	// An entry kept longer ago than the refresh interval is kept again.
	lookup.processContainers.Set(
		42,
		otherContainerID,
		exitedProcessTimeout-2*processRefreshInterval,
	)
	stale := lookup.processContainers.Get(42).ExpiresAt()

	_, err = lookup.containerIDForProcess(mock, 42, time.Time{})
	require.NoError(t, err)
	require.True(t, lookup.processContainers.Get(42).ExpiresAt().After(stale))
}

// TestBacklogIsKeptPerContainer asserts that a process reusing a PID in another
// container never gets the backlog of the previous one.
func TestBacklogIsKeptPerContainer(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	line := &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 42}
	require.NoError(t, sut.addToBacklog("old-container", line))

	sut.dispatchBacklog(node, &types.ContainerInfo{ContainerID: "new-container"})
	require.Equal(t, 1, sut.auditLineCache.Len())

	sut.dispatchBacklog(node, &types.ContainerInfo{ContainerID: "old-container"})
	require.Zero(t, sut.auditLineCache.Len())
}

// TestBacklogKeepsDistinctLinesWhenFull asserts that a full backlog still
// keeps the lines which differ from the kept ones, so that a recording does
// not miss the syscalls a container issues after a burst of other ones.
func TestBacklogKeepsDistinctLinesWhenFull(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	const containerID = "container"

	line := func(timestamp string, syscallID int32) *types.AuditLine {
		return &types.AuditLine{
			AuditType:    types.AuditTypeSeccomp,
			ProcessID:    1,
			TimestampID:  timestamp,
			SystemCallID: syscallID,
		}
	}

	for i := range int32(auditBacklogMax) {
		require.NoError(t, sut.addToBacklog(containerID, line(strconv.Itoa(int(i)), i%2)))
	}

	// A repeated line is dropped, also from another process, while a new
	// syscall is kept.
	require.NoError(t, sut.addToBacklog(containerID, line("repeated", 1)))

	forked := line("forked", 1)
	forked.ProcessID = 2
	require.NoError(t, sut.addToBacklog(containerID, forked))
	require.NoError(t, sut.addToBacklog(containerID, line("listen", 50)))
	require.NoError(t, sut.addToBacklog(containerID, line("listen-again", 50)))

	backlog := sut.auditLineCache.Get(containerID).Value()
	lines, dropped := backlog.snapshot()
	require.Len(t, lines, auditBacklogMax+1)
	require.Equal(t, "listen", lines[auditBacklogMax].TimestampID)
	require.EqualValues(t, 3, dropped)

	// The distinct lines are bounded as well.
	for i := range int32(auditBacklogDistinctMax) {
		require.NoError(t, sut.addToBacklog(containerID, line("", 100+i)))
	}

	lines, dropped = backlog.snapshot()
	require.Len(t, lines, auditBacklogDistinctMax)
	// The lines over the bound count as dropped.
	require.Greater(t, dropped, uint64(3))
}

// TestBacklogIsDispatchedPerContainer asserts that finding a container sends
// the backlog of all of its processes, not only the one of the process whose
// line found it: the others may stay idle until their lines expire.
func TestBacklogIsDispatchedPerContainer(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	info := &types.ContainerInfo{ContainerID: "container", SeccompRecordProfile: "profile"}

	for _, pid := range []int{1, 2} {
		require.NoError(t, sut.addToBacklog(info.ContainerID, &types.AuditLine{
			AuditType: types.AuditTypeSeccomp, ProcessID: pid, SystemCallID: 0,
		}))
	}

	require.NoError(t, sut.addToBacklog("container-2", &types.AuditLine{
		AuditType: types.AuditTypeSeccomp, ProcessID: 3,
	}))

	require.Equal(t, 2, sut.auditLineCache.Len())

	sut.dispatchBacklog(node, info)

	require.Equal(t, 1, sut.auditLineCache.Len(), "only the other container is left")
	_, found := sut.syscalls.get("profile", false)
	require.True(t, found)
}

// TestRunDispatchesBacklogOnPodUpdate asserts that the lines of a container
// its pod does not tell yet are kept, without holding up the lines of other
// containers, and sent once the pod tells the container.
func TestRunDispatchesBacklogOnPodUpdate(t *testing.T) {
	t.Parallel()

	lineChan := make(chan *types.AuditLine)
	mock := &enricherfakes.FakeImpl{}
	mock.StartTailReturns(lineChan, nil)
	mock.ContainerIDForPIDCalls(func(
		_ *ttlcache.Cache[string, string], pid int,
	) (string, time.Duration, error) {
		if pid == 3 {
			return otherContainerID, 0, nil
		}

		return containerID, 0, nil
	})

	other := runningPod()
	other.Name = "other"
	other.Status.ContainerStatuses[0].ContainerID = ""

	pods := podindextest.New(*runningPod(), *other)
	mock.PodListerWatcherReturns(pods)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

	runErr := startRun(t, sut)

	// The container of the other pod is still being created.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 3}

	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 3}

	require.Eventually(t, func() bool {
		item := sut.auditLineCache.Get(otherContainerID)
		if item == nil {
			return false
		}

		lines, _ := item.Value().snapshot()

		return len(lines) == 2
	}, time.Minute, time.Millisecond)

	// The lines of a known container are sent in the meantime.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 1}

	waitForCallCount(t, mock.SendMetricCallCount, 1)

	other.Status.ContainerStatuses[0].ContainerID = crioPrefix + otherContainerID
	pods.Modify(other)

	waitForCallCount(t, mock.SendMetricCallCount, 3)
	require.Zero(t, sut.auditLineCache.Len())

	for i := 1; i < 3; i++ {
		_, req := mock.SendMetricArgsForCall(i)
		require.Equal(t, "other", req.GetPod())
	}

	stopRun(t, lineChan, runErr)
}

// newRunSut returns an enricher for Run whose audit log is lineChan.
func newRunSut(t *testing.T, lineChan chan *types.AuditLine) (*Enricher, *enricherfakes.FakeImpl) {
	t.Helper()

	mock := &enricherfakes.FakeImpl{}
	mock.StartTailReturns(lineChan, nil)
	mock.PodListerWatcherReturns(podindextest.New(*runningPod()))
	mock.ListenReturns(&fakeListener{}, nil)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

	return sut, mock
}

// TestRunStopsWithContext asserts that Run returns once its context is done,
// and releases the metrics connection.
func TestRunStopsWithContext(t *testing.T) {
	t.Parallel()

	sut, mock := newRunSut(t, make(chan *types.AuditLine))

	ctx, cancel := context.WithCancel(t.Context())
	runErr := make(chan error, 1)

	go func() { runErr <- sut.Run(ctx) }()

	waitForCallCount(t, mock.StartTailCallCount, 1)
	cancel()

	select {
	case err := <-runErr:
		require.NoError(t, err)
	case <-time.After(time.Minute):
		t.Fatal("Run did not return")
	}

	waitForCallCount(t, mock.CloseCallCount, 1)
}

// TestRunClosesListenerOnChownFailure asserts that the listener of the GRPC
// server is not leaked if its socket cannot be handed to the rootless user.
func TestRunClosesListenerOnChownFailure(t *testing.T) {
	t.Parallel()

	sut, mock := newRunSut(t, make(chan *types.AuditLine))

	listener := &fakeListener{}
	mock.ListenReturns(listener, nil)
	mock.ChownReturns(errTest)

	require.ErrorIs(t, sut.Run(t.Context()), errTest)
	require.True(t, listener.closed.Load())
}

// TestBacklogKeepsItsTTL asserts that adding lines to a backlog does not
// extend its lifetime, which counts from its first line.
func TestBacklogKeepsItsTTL(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	line := func(syscallID int32) *types.AuditLine {
		return &types.AuditLine{AuditType: types.AuditTypeSeccomp, SystemCallID: syscallID}
	}

	require.NoError(t, sut.addToBacklog(containerID, line(0)))

	expiresAt := sut.auditLineCache.Get(containerID).ExpiresAt()

	// Adding the line from now on would move the expiry.
	require.Eventually(t, func() bool {
		return time.Now().Add(backlogTimeout).After(expiresAt)
	}, time.Minute, time.Microsecond)

	require.NoError(t, sut.addToBacklog(containerID, line(1)))

	item := sut.auditLineCache.Get(containerID)
	require.Equal(t, expiresAt, item.ExpiresAt())

	lines, _ := item.Value().snapshot()
	require.Len(t, lines, 2)
}

// TestBacklogAddCountsDropped asserts that adding a line tells the number of
// the dropped lines.
func TestBacklogAddCountsDropped(t *testing.T) {
	t.Parallel()

	backlog := &auditBacklog{seen: map[types.AuditLine]struct{}{}}
	line := &types.AuditLine{AuditType: types.AuditTypeSeccomp}

	for range auditBacklogMax {
		kept, dropped := backlog.add(line)
		require.True(t, kept)
		require.Zero(t, dropped)
	}

	for want := range uint64(3) {
		kept, dropped := backlog.add(line)
		require.False(t, kept)
		require.Equal(t, want+1, dropped)
	}
}
