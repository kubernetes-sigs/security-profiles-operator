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
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// newClusterRecorder returns a recorder which runs in-cluster with fakes.
func newClusterRecorder(
	recordSeccomp, recordAppArmor bool,
) (*BpfRecorder, *bpfrecorderfakes.FakeImpl) {
	sut := New("", logr.Discard(), recordSeccomp, recordAppArmor)
	mock := &bpfrecorderfakes.FakeImpl{}
	sut.impl = mock
	sut.clientset = &kubernetes.Clientset{}

	return sut, mock
}

func pidKey(pid uint32, key uint64) []byte {
	raw := make([]byte, 16)
	binary.NativeEndian.PutUint32(raw[0:4], pid)
	binary.NativeEndian.PutUint64(raw[8:16], key)

	return raw
}

// TestFindProfileRemembersMissingContainers asserts that a container which is
// not in the cluster, like one of podman on the node, is looked up once and
// not with every process it starts.
func TestFindProfileRemembersMissingContainers(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	mock.ListPodsReturns(podWithContainer(nil), nil)

	const other = "0000000000000000000000000000000000000000000000000000000000000001"

	_, err := sut.findProfileForContainerID(other)
	require.ErrorIs(t, err, errContainerNotInCluster)
	// No pod is waiting for its containers, so nothing is retried.
	require.Equal(t, 1, mock.ListPodsCallCount())

	_, err = sut.findProfileForContainerID(other)
	require.ErrorIs(t, err, errContainerNotInCluster)
	require.Equal(t, 1, mock.ListPodsCallCount())

	// A new recording looks again.
	require.NoError(t, sut.StopRecording())

	_, err = sut.findProfileForContainerID(other)
	require.ErrorIs(t, err, errContainerNotInCluster)
	require.Equal(t, 2, mock.ListPodsCallCount())
}

// TestFindProfileWaitsForCreatedContainers asserts that the lookup is retried
// while the pod status does not list every container yet.
func TestFindProfileWaitsForCreatedContainers(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)

	creating := podWithContainer(nil)
	creating.Items[0].Status.ContainerStatuses[0].ContainerID = ""
	creating.Items[0].Status.ContainerStatuses[0].State.Waiting = &v1.ContainerStateWaiting{
		Reason: "ContainerCreating",
	}

	mock.ListPodsReturnsOnCall(0, creating, nil)
	mock.ListPodsReturnsOnCall(1, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}), nil)

	got, err := sut.findProfileForContainerID(containerID)
	require.NoError(t, err)
	require.Equal(t, profile, got)
	require.Equal(t, 2, mock.ListPodsCallCount())
}

// TestCacheProfilesOfUnresolvedContainers asserts that a container whose lookup
// gave up gets its profile once the pod status tells its ID.
func TestCacheProfilesOfUnresolvedContainers(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)

	// Nothing to look up.
	sut.cacheProfilesOfUnresolvedContainers(t.Context())
	require.Zero(t, mock.ListPodsCallCount())

	const key = 7

	sut.containerKeys.Insert(key, containerID)
	sut.containersNotFound.Set(containerID, struct{}{}, ttlcache.DefaultTTL)

	mock.ListPodsReturns(podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}), nil)

	sut.cacheProfilesOfUnresolvedContainers(t.Context())
	require.Equal(t, 1, mock.ListPodsCallCount())

	got, ok := sut.profileOfKey(key)
	require.True(t, ok)
	require.Equal(t, profile, got)

	// Resolved containers need no lookup.
	sut.cacheProfilesOfUnresolvedContainers(t.Context())
	require.Equal(t, 1, mock.ListPodsCallCount())
}

// TestFindProfileWaitsForRestartedContainers asserts that the lookup is retried
// while a recorded pod still lists the previous run of a restarted container.
func TestFindProfileWaitsForRestartedContainers(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)

	annotations := map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}

	previousRun := podWithContainer(annotations)
	previousRun.Items[0].Status.ContainerStatuses[0].ContainerID = crioPrefix +
		"0000000000000000000000000000000000000000000000000000000000000002"

	mock.ListPodsReturnsOnCall(0, previousRun, nil)
	mock.ListPodsReturnsOnCall(1, podWithContainer(annotations), nil)

	got, err := sut.findProfileForContainerID(containerID)
	require.NoError(t, err)
	require.Equal(t, profile, got)
	require.Equal(t, 2, mock.ListPodsCallCount())
}

// TestFindProfileSharesLookups asserts that the handlers of the processes of
// one container share a single lookup.
func TestFindProfileSharesLookups(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)

	release := make(chan struct{})

	mock.ListPodsStub = func(context.Context, *kubernetes.Clientset, string) (*v1.PodList, error) {
		<-release

		return podWithContainer(map[string]string{
			config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
		}), nil
	}

	const lookups = 8

	var wg sync.WaitGroup

	for range lookups {
		wg.Go(func() {
			got, err := sut.findProfileForContainerID(containerID)
			assertNoErrorEqual(t, err, profile, got)
		})
	}

	require.Eventually(t, func() bool {
		return mock.ListPodsCallCount() == 1
	}, time.Minute, time.Millisecond)

	close(release)
	wg.Wait()

	require.Equal(t, 1, mock.ListPodsCallCount())
}

func assertNoErrorEqual(t *testing.T, err error, want, got string) {
	t.Helper()

	if err != nil || want != got {
		t.Errorf("got %q, %v, want %q", got, err, want)
	}
}

func TestContainersPending(t *testing.T) {
	t.Parallel()

	withStatus := func(status v1.ContainerStatus) *v1.Pod {
		return &v1.Pod{
			Spec:   v1.PodSpec{Containers: []v1.Container{{Name: "ctr"}}},
			Status: v1.PodStatus{ContainerStatuses: []v1.ContainerStatus{status}},
		}
	}

	for name, tc := range map[string]struct {
		pod  *v1.Pod
		want bool
	}{
		"running": {
			pod:  withStatus(v1.ContainerStatus{ContainerID: crioPrefix + containerID}),
			want: false,
		},
		"no status yet": {
			pod:  &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{Name: "ctr"}}}},
			want: true,
		},
		"creating": {
			pod: withStatus(v1.ContainerStatus{State: v1.ContainerState{
				Waiting: &v1.ContainerStateWaiting{Reason: "ContainerCreating"},
			}}),
			want: true,
		},
		"image cannot be pulled": {
			pod: withStatus(v1.ContainerStatus{State: v1.ContainerState{
				Waiting: &v1.ContainerStateWaiting{Reason: "ImagePullBackOff"},
			}}),
			want: false,
		},
		"terminated without ID": {
			pod: withStatus(v1.ContainerStatus{State: v1.ContainerState{
				Terminated: &v1.ContainerStateTerminated{Reason: "ContainerStatusUnknown"},
			}}),
			want: false,
		},
		"failed without statuses": {
			pod: &v1.Pod{
				Spec:   v1.PodSpec{Containers: []v1.Container{{Name: "ctr"}}},
				Status: v1.PodStatus{Phase: v1.PodFailed},
			},
			want: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, containersPending(tc.pod))
		})
	}
}

// TestVerifyProcess asserts that a PID which belongs to another process than
// the reported one is detected.
func TestVerifyProcess(t *testing.T) {
	t.Parallel()

	startedAt := func(started time.Duration) func(int) (time.Duration, error) {
		return func(int) (time.Duration, error) { return started, nil }
	}

	inMntns := func(link string) func(string) (string, error) {
		return func(string) (string, error) { return link, nil }
	}

	require.NoError(t, verifyProcess(42, 7, time.Hour, startedAt(time.Minute), inMntns("mnt:[7]")))

	// The time is not known.
	require.NoError(t, verifyProcess(42, 7, 0, startedAt(time.Minute), inMntns("mnt:[7]")))

	err := verifyProcess(42, 7, time.Minute, startedAt(time.Hour), inMntns("mnt:[7]"))
	require.ErrorIs(t, err, errProcessChanged)

	err = verifyProcess(42, 7, time.Hour, startedAt(time.Minute), inMntns("mnt:[8]"))
	require.ErrorIs(t, err, errProcessChanged)

	err = verifyProcess(42, 7, time.Hour, func(int) (time.Duration, error) {
		return 0, os.ErrNotExist
	}, inMntns("mnt:[7]"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

// TestNewPidEventOfReusedPid asserts that a key is neither mapped nor excluded
// when its reported PID belongs to another process by now.
func TestNewPidEventOfReusedPid(t *testing.T) {
	t.Parallel()

	for _, lookupErr := range []error{nil, util.ErrContainerIDNotFound} {
		sut, mock := newClusterRecorder(true, true)
		sut.uniqueKeys = true
		sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

		mock.ContainerIDForPIDReturns(containerID, lookupErr)
		mock.VerifyProcessReturns(errProcessChanged)
		mock.ListPodsReturns(podWithContainer(map[string]string{
			config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
		}), nil)

		sut.AppArmor.handleFileEvent(fileEvent(7, flagRead, "/etc/passwd"))

		sut.handleNewPidEvent(newPidEvent{
			pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load(),
		})

		require.Zero(t, sut.containerKeys.Size())
		require.Zero(t, mock.UpdateValue64CallCount(), "the key must not be excluded")
		require.Contains(t, sut.AppArmor.recordedFiles, recordingKey(7))
	}
}

// TestNewPidEventResolvesCgroup asserts that a cgroup key is mapped by its
// path, which works without the reported process.
func TestNewPidEventResolvesCgroup(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	sut.uniqueKeys = true
	sut.cgroupKeys = true

	mock.CgroupPathForIDReturns(
		"/kubepods.slice/kubepods-pod1.slice/crio-"+containerID+".scope", nil,
	)
	mock.ContainerIDForPIDReturns("", util.ErrProcessNotFound)
	mock.ListPodsReturns(podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}), nil)

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Zero(t, mock.ContainerIDForPIDCallCount())
	require.Equal(t, []uint64{7}, sut.containerKeys.Keys(containerID))

	// Another process of the container needs no lookup.
	sut.handleNewPidEvent(
		newPidEvent{pid: 43, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Equal(t, 1, mock.CgroupPathForIDCallCount())
	require.Equal(t, 1, mock.ListPodsCallCount())
}

// TestNewPidEventFallsBackToPid asserts that a cgroup path without container
// is left to the lookup by PID, which only excludes a verified process.
func TestNewPidEventFallsBackToPid(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	sut.uniqueKeys = true
	sut.cgroupKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	mock.CgroupPathForIDReturns("/system.slice/sshd.service", nil)
	mock.ContainerIDForPIDReturns("", util.ErrContainerIDNotFound)

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Equal(t, 1, mock.ContainerIDForPIDCallCount())
	require.Equal(t, 1, mock.VerifyProcessCallCount())
	require.Equal(t, 1, mock.UpdateValue64CallCount())
}

// TestScheduleNewPidEventReportsDroppedAgain asserts that a process whose event
// did not fit into the queue is removed from the active processes once the
// queue has room again, so that the BPF program reports it again, but not
// while the queue is still full.
func TestScheduleNewPidEventReportsDroppedAgain(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	sut.activePidsBpfMap = &libbpfgo.BPFMap{}

	sut.startPidHandlers.Do(func() {})

	for range newPidQueueSize {
		sut.newPidEvents <- newPidEvent{}
	}

	sut.scheduleNewPidEvent(42, 1, 7)
	sut.scheduleNewPidEvent(42, 1, 7)

	sut.reportDroppedPidsAgain()
	require.Zero(t, mock.DeleteActivePidCallCount())

	for range newPidQueueSize {
		<-sut.newPidEvents
	}

	sut.reportDroppedPidsAgain()
	require.Equal(t, 1, mock.DeleteActivePidCallCount())

	_, pid, key := mock.DeleteActivePidArgsForCall(0)
	require.Equal(t, uint32(42), pid)
	require.Equal(t, uint64(7), key)
}

// TestSweepStaleKeys asserts that the data of keys without container and
// processes is dropped after a grace period, and only theirs.
func TestSweepStaleKeys(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(false, true)
	sut.activePidsBpfMap = &libbpfgo.BPFMap{}
	atomic.StoreInt64(&sut.startRequests, 1)

	const (
		mapped uint64 = 1
		alive  uint64 = 2
		stale  uint64 = 3
	)

	for _, key := range []uint64{mapped, alive, stale} {
		sut.AppArmor.handleFileEvent(fileEvent(key, flagRead, "/etc/passwd"))
	}

	sut.containerKeys.Insert(mapped, containerID)
	sut.containerIDToProfileMap.Insert(containerID, profile)

	mock.MapKeysReturns([][]byte{pidKey(100, alive), pidKey(200, stale)}, nil)
	mock.StatCalls(func(path string) (os.FileInfo, error) {
		if path == "/proc/100" {
			return os.Stat("/")
		}

		return nil, os.ErrNotExist
	})

	sut.sweepStaleKeys()
	require.ElementsMatch(t, []uint64{mapped, alive, stale}, sut.AppArmor.GetKnownKeys())

	sut.sweepStaleKeys()
	require.ElementsMatch(t, []uint64{mapped, alive}, sut.AppArmor.GetKnownKeys())
	require.Empty(t, sut.staleKeys)
}

// TestSweepStaleKeysUnknownProcesses asserts that no data is dropped while the
// recorded processes cannot be listed.
func TestSweepStaleKeysUnknownProcesses(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(false, true)
	sut.activePidsBpfMap = &libbpfgo.BPFMap{}
	atomic.StoreInt64(&sut.startRequests, 1)

	sut.AppArmor.handleFileEvent(fileEvent(3, flagRead, "/etc/passwd"))
	mock.MapKeysReturns(nil, errors.New("map error"))

	for range staleKeySweeps {
		sut.sweepStaleKeys()
	}

	require.Equal(t, []uint64{3}, sut.AppArmor.GetKnownKeys())
}

// TestSweepStaleKeysKeepsExistingCgroups asserts that the data of a cgroup
// which still exists is kept, it can get new processes.
func TestSweepStaleKeysKeepsExistingCgroups(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(false, true)
	sut.cgroupKeys = true
	atomic.StoreInt64(&sut.startRequests, 1)

	sut.AppArmor.handleFileEvent(fileEvent(3, flagRead, "/etc/passwd"))
	mock.CgroupPathForIDReturns("/system.slice/podman.service", nil)

	for range staleKeySweeps {
		sut.sweepStaleKeys()
	}

	require.Equal(t, []uint64{3}, sut.AppArmor.GetKnownKeys())
}

// TestReleaseAbandonedRecording asserts that a recording nobody stopped is
// stopped once no pod on the node is recorded any more for a while.
func TestReleaseAbandonedRecording(t *testing.T) {
	t.Parallel()

	now := time.Now()

	sut, mock := newRecordingRecorder(t, false, false)
	sut.clientset = &kubernetes.Clientset{}
	sut.now = func() time.Time { return now }

	// A Stop got lost.
	_, err := sut.Start(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)

	recorded := podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	})
	mock.ListPodsReturns(recorded, nil)

	now = now.Add(time.Hour)

	sut.releaseAbandonedRecording(t.Context())
	require.EqualValues(t, 2, atomic.LoadInt64(&sut.startRequests))

	mock.ListPodsReturns(podWithContainer(nil), nil)

	sut.releaseAbandonedRecording(t.Context())

	now = now.Add(abandonedRecordingTimeout / 2)

	sut.releaseAbandonedRecording(t.Context())
	require.EqualValues(t, 2, atomic.LoadInt64(&sut.startRequests))

	// A new recording starts the wait over.
	_, err = sut.Start(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)

	now = now.Add(abandonedRecordingTimeout)

	sut.releaseAbandonedRecording(t.Context())
	require.EqualValues(t, 3, atomic.LoadInt64(&sut.startRequests))

	now = now.Add(abandonedRecordingTimeout)

	sut.releaseAbandonedRecording(t.Context())
	require.Zero(t, atomic.LoadInt64(&sut.startRequests))

	// The client stops its recordings afterwards.
	_, err = sut.Stop(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)
	require.Zero(t, atomic.LoadInt64(&sut.startRequests))
}

// TestReleaseAbandonedRecordingKeepsUncollectedProfiles asserts that the data
// of profiles which are still to be collected is kept for the retries of the
// collection.
func TestReleaseAbandonedRecordingKeepsUncollectedProfiles(t *testing.T) {
	t.Parallel()

	now := time.Now()

	sut, mock := newRecordingRecorder(t, false, false)
	sut.clientset = &kubernetes.Clientset{}
	sut.now = func() time.Time { return now }

	mock.ListPodsReturns(podWithContainer(nil), nil)
	sut.containerIDToProfileMap.Insert(containerID, profile)

	sut.releaseAbandonedRecording(t.Context())

	now = now.Add(abandonedRecordingTimeout)

	sut.releaseAbandonedRecording(t.Context())
	require.EqualValues(t, 1, atomic.LoadInt64(&sut.startRequests))

	now = now.Add(uncollectedRecordingTimeout)

	sut.releaseAbandonedRecording(t.Context())
	require.Zero(t, atomic.LoadInt64(&sut.startRequests))
}

func TestRecordsBpf(t *testing.T) {
	t.Parallel()

	withAnnotations := func(phase v1.PodPhase, annotations map[string]string) *v1.Pod {
		return &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{Annotations: annotations},
			Status:     v1.PodStatus{Phase: phase},
		}
	}

	require.True(t, recordsBpf(withAnnotations(v1.PodRunning, map[string]string{
		config.ApparmorProfileRecordBpfAnnotationKey + "ctr": profile,
	})))
	require.False(t, recordsBpf(withAnnotations(v1.PodRunning, map[string]string{
		config.SeccompProfileRecordLogsAnnotationKey + "ctr": profile,
	})))
	require.False(t, recordsBpf(withAnnotations(v1.PodSucceeded, map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	})))
	require.False(t, recordsBpf(withAnnotations(v1.PodRunning, nil)))
}
