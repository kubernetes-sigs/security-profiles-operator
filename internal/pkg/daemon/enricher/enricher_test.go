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
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	node        = "test-node"
	namespace   = "test-namespace"
	pod         = "test-pod"
	executable  = "/bin/busybox"
	crioPrefix  = "cri-o://"
	containerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
)

var errTest = errors.New("test")

// waitForCallCount spins until want calls have been recorded, failing the test
// rather than hanging until the package timeout if that never happens.
func waitForCallCount(t *testing.T, count func() int, want int) {
	t.Helper()

	// Generous: the backlog cases wait on a container lookup that retries with
	// the production backoff. The point of the deadline is only to fail instead
	// of hanging until the package timeout.
	deadline := time.Now().Add(3 * time.Minute)

	for count() != want {
		if time.Now().After(deadline) {
			t.Fatalf("expected %d calls, got %d before the deadline", want, count())
		}

		time.Sleep(time.Millisecond)
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		runAsync bool
		prepare  func(*enricherfakes.FakeImpl, chan *types.AuditLine)
		assert   func(*Enricher, *enricherfakes.FakeImpl, chan *types.AuditLine, error)
	}{
		{ // success
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
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
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
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

				require.NoError(t, err)
			},
		},

		{ // failure on Dial
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on MetricsAuditInc
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.AuditIncReturns(nil, errTest)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on Tail
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.StartTailReturns(nil, errTest)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},
		{ // failure on Listen
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.ListenReturns(nil, errTest)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},

		{ // failure on Chown
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				mock.ChownReturns(errTest)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},
		{ // failure on log iteration
			runAsync: false,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.DialReturns(nil, errTest)
				close(lineChan)
				mock.StartTailReturns(lineChan, nil)
				mock.TailErrReturns(errTest)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				require.Error(t, err)
			},
		},
		{ // success, but metrics send failed
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
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
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				waitForCallCount(t, mock.StartTailCallCount, 1)

				lineChan <- &types.AuditLine{
					AuditType: types.AuditTypeSeccomp,
				}

				waitForCallCount(t, mock.SendMetricCallCount, 1)

				require.NoError(t, err)
			},
		},
		{ // success, but using the backlog
			runAsync: true,
			prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
				mock.StartTailReturns(lineChan, nil)
				mock.ContainerIDForPIDReturns(containerID, nil)
			},
			assert: func(sut *Enricher, mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine, err error) {
				// The pod status lists the container only once the test says
				// so, instead of after a number of lookups which depends on
				// the retry backoff.
				var containerListed atomic.Bool

				mock.ListPodsCalls(func(
					context.Context, kubernetes.Interface, string,
				) (*v1.PodList, error) {
					status := v1.ContainerStatus{
						State: v1.ContainerState{
							Waiting: &v1.ContainerStateWaiting{Reason: "ContainerCreating"},
						},
					}
					if containerListed.Load() {
						status = v1.ContainerStatus{ContainerID: crioPrefix + containerID}
					}

					return &v1.PodList{Items: []v1.Pod{{
						ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace},
						Status:     v1.PodStatus{ContainerStatuses: []v1.ContainerStatus{status}},
					}}}, nil
				})

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

				// The line is backlogged once all lookups failed.
				waitForCallCount(t, sut.auditLineCache.Len, 1)
				require.Zero(t, mock.SendMetricCallCount())

				// The next line finds the container and flushes the backlog
				// before it is dispatched itself.
				containerListed.Store(true)

				lineChan <- &types.AuditLine{
					AuditType: types.AuditTypeSeccomp,
					ProcessID: avcLine.ProcessID,
				}

				waitForCallCount(t, sut.auditLineCache.Len, 0)
				waitForCallCount(t, mock.SendMetricCallCount, 2)

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
		sut.nodeName = node
		// The backlog case looks the container up again right away, which
		// the cache of missing containers would otherwise answer.
		sut.missingContainers = ttlcache.New(ttlcache.WithTTL[string, struct{}](time.Nanosecond))
		// Do not spend the production backoffs as test wall-clock time.
		sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}
		sut.containerBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 3}

		if tc.runAsync {
			// Run only returns when the enricher shuts down, so the async cases
			// assert on its side effects rather than its return value. Sharing
			// an `err` variable with the goroutine would be a data race.
			//nolint:errcheck // Run only returns on shutdown; see above.
			go func() { sut.Run() }()

			tc.assert(sut, mock, lineChan, nil)
		} else {
			tc.assert(sut, mock, lineChan, sut.Run())
		}
	}
}

func TestRunWithoutNodeName(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, "")

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = &enricherfakes.FakeImpl{}

	require.Error(t, sut.Run())
}

// TestRunDropsLinesWithoutContainer asserts that lines of host processes and of
// processes which are gone are not kept around: a later line with the same
// PID may come from another process which reused it.
func TestRunDropsLinesWithoutContainer(t *testing.T) {
	t.Parallel()

	for _, lookupErr := range []error{util.ErrContainerIDNotFound, os.ErrNotExist} {
		lineChan := make(chan *types.AuditLine)
		mock := &enricherfakes.FakeImpl{}
		mock.StartTailReturns(lineChan, nil)
		mock.ContainerIDForPIDReturnsOnCall(0, "", lookupErr)
		mock.ContainerIDForPIDReturnsOnCall(1, containerID, nil)
		mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace},
			Status: v1.PodStatus{
				ContainerStatuses: []v1.ContainerStatus{{
					ContainerID: crioPrefix + containerID,
				}},
			},
		}}}, nil)

		sut, err := New(logr.Discard(), nil)
		require.NoError(t, err)

		sut.impl = mock
		sut.nodeName = node
		sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

		//nolint:errcheck // Run only returns on shutdown.
		go func() { sut.Run() }()

		lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 42}

		waitForCallCount(t, mock.ContainerIDForPIDCallCount, 1)
		require.Zero(t, sut.auditLineCache.Len())

		// The process reusing the PID gets only its own line.
		lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 42}

		waitForCallCount(t, mock.SendMetricCallCount, 1)
		require.Zero(t, sut.auditLineCache.Len())
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
	mock.ContainerIDForPIDReturnsOnCall(0, containerID, nil)
	mock.ContainerIDForPIDReturns("", os.ErrNotExist)
	mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
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
	}}}, nil)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}

	//nolint:errcheck // Run only returns on shutdown.
	go func() { sut.Run() }()

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

	item := sut.syscalls.Get(recordProfile)
	require.NotNil(t, item)
	require.ElementsMatch(t, names, item.Value().UnsortedList())
}

// TestContainerIDForProcessForgetsReusedPID asserts that the container of an
// exited process is not used any more once a process outside of a container
// runs with its PID.
func TestContainerIDForProcessForgetsReusedPID(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}
	mock.ContainerIDForPIDReturnsOnCall(0, containerID, nil)
	mock.ContainerIDForPIDReturnsOnCall(1, "", util.ErrContainerIDNotFound)
	mock.ContainerIDForPIDReturnsOnCall(2, "", os.ErrNotExist)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock

	cID, err := sut.containerIDForProcess(42)
	require.NoError(t, err)
	require.Equal(t, containerID, cID)

	_, err = sut.containerIDForProcess(42)
	require.ErrorIs(t, err, util.ErrContainerIDNotFound)

	_, err = sut.containerIDForProcess(42)
	require.ErrorIs(t, err, os.ErrNotExist)
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

// TestBacklogIsDispatchedPerContainer asserts that finding a container sends
// the backlog of all of its processes, not only the one of the process whose
// line found it: the others may stay idle until their lines expire.
func TestBacklogIsDispatchedPerContainer(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	info := &types.ContainerInfo{ContainerID: "container", RecordProfile: "profile"}

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
	require.NotNil(t, sut.syscalls.Get("profile"))
}

// TestRunDispatchesBacklogAfterMissingWindow asserts that the lines of a
// container which was missing from the pod list are sent once a later line
// finds it, after the missing containers cache let it be looked up again.
func TestRunDispatchesBacklogAfterMissingWindow(t *testing.T) {
	t.Parallel()

	lineChan := make(chan *types.AuditLine)
	mock := &enricherfakes.FakeImpl{}
	mock.StartTailReturns(lineChan, nil)
	mock.ContainerIDForPIDReturns(containerID, nil)
	mock.ListPodsReturnsOnCall(0, &v1.PodList{}, nil)
	mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{{ContainerID: crioPrefix + containerID}},
		},
	}}}, nil)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}
	sut.containerBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 1}
	sut.missingContainers = ttlcache.New(ttlcache.WithTTL[string, struct{}](time.Hour))

	//nolint:errcheck // Run only returns on shutdown.
	go func() { sut.Run() }()

	// The first process is not found and backlogged.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 1}

	waitForCallCount(t, sut.auditLineCache.Len, 1)

	// Within the missing window, the container is not looked up again.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 2}

	require.Eventually(t, func() bool {
		item := sut.auditLineCache.Get(containerID)

		return item != nil && len(item.Value()) == 2
	}, time.Minute, time.Millisecond)
	require.Equal(t, 1, mock.ListPodsCallCount())

	// The missing window ends.
	sut.missingContainers.Delete(containerID)

	// Another process finds the container, which sends everything.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 3}

	waitForCallCount(t, mock.SendMetricCallCount, 3)
	require.Zero(t, sut.auditLineCache.Len())
}

// TestRunDispatchesBacklogOfListedContainer asserts that the backlog of a
// container is sent once listing the pods for another container finds it,
// without waiting for another line of its own.
func TestRunDispatchesBacklogOfListedContainer(t *testing.T) {
	t.Parallel()

	const otherContainerID = "e1d4c1dbd3b5d9a4e9e2f6f5a1c8f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"

	lineChan := make(chan *types.AuditLine)
	mock := &enricherfakes.FakeImpl{}
	mock.StartTailReturns(lineChan, nil)
	mock.ContainerIDForPIDReturnsOnCall(0, containerID, nil)
	mock.ContainerIDForPIDReturnsOnCall(1, otherContainerID, nil)
	mock.ListPodsReturnsOnCall(0, &v1.PodList{}, nil)
	mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{
				{ContainerID: crioPrefix + containerID},
				{ContainerID: crioPrefix + otherContainerID},
			},
		},
	}}}, nil)

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}
	sut.containerBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 1}

	//nolint:errcheck // Run only returns on shutdown.
	go func() { sut.Run() }()

	// The container is not listed yet.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 1}

	waitForCallCount(t, sut.auditLineCache.Len, 1)

	// Listing the pods for another container finds it as well.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 2}

	waitForCallCount(t, mock.SendMetricCallCount, 2)
	require.Zero(t, sut.auditLineCache.Len())
}
