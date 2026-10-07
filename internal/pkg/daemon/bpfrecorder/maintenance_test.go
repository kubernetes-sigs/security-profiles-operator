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
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
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
// not in the cluster, like one of podman on the node, is waited for once and
// not with every process it starts.
func TestFindProfileRemembersMissingContainers(t *testing.T) {
	t.Parallel()

	sut, _ := newClusterRecorder(true, false)
	lw := watchPods(t, sut, podWithContainer(nil))

	const other = "0000000000000000000000000000000000000000000000000000000000000001"

	_, err := sut.findProfileForContainerID(other)
	require.ErrorIs(t, err, errContainerNotInCluster)
	require.True(t, sut.containersNotFound.Has(other))

	// Not waited for again, even if a pod has it by now.
	otherPod := podWithContainer(nil)
	otherPod.Name = "other"
	otherPod.Status.ContainerStatuses[0].ContainerID = crioPrefix + other
	lw.Add(otherPod)

	require.Eventually(t, func() bool {
		_, ok := sut.pods.Get(other)

		return ok
	}, time.Minute, time.Millisecond)

	_, err = sut.findProfileForContainerID(other)
	require.ErrorIs(t, err, errContainerNotInCluster)

	// A new recording looks again.
	require.NoError(t, sut.StopRecording())

	_, err = sut.findProfileForContainerID(other)
	require.ErrorIs(t, err, errNoProfileForContainer)
}

// TestFindProfileWaitsForContainers asserts that the lookup waits for the pod
// status to tell the container, which it does only once the container got
// created, or started again after a restart.
func TestFindProfileWaitsForContainers(t *testing.T) {
	t.Parallel()

	annotations := map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}

	creating := podWithContainer(annotations)
	creating.Status.ContainerStatuses[0].ContainerID = ""

	// The status keeps the ID of the previous container until the new one
	// started.
	previousRun := podWithContainer(annotations)
	previousRun.Status.ContainerStatuses[0].ContainerID = crioPrefix +
		"0000000000000000000000000000000000000000000000000000000000000002"
	previousRun.Status.ContainerStatuses[0].State.Terminated = &v1.ContainerStateTerminated{
		ExitCode: 1,
	}

	for name, before := range map[string]*v1.Pod{
		"created":   creating,
		"restarted": previousRun,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut, _ := newClusterRecorder(true, false)
			lw := watchPods(t, sut, before)
			sut.containerLookupTimeout = time.Minute

			const lookups = 8

			// The handlers of the processes of the container share the
			// lookup.
			results := make(chan error, lookups)

			for range lookups {
				go func() {
					got, err := sut.findProfileForContainerID(containerID)
					if err == nil && got != profile {
						err = fmt.Errorf("got profile %q", got)
					}

					results <- err
				}()
			}

			lw.Modify(podWithContainer(annotations))

			for range lookups {
				require.NoError(t, <-results)
			}

			require.False(t, sut.containersNotFound.Has(containerID))
		})
	}
}

// TestFindProfileDoesNotWaitForUnknownContainers asserts that a container
// which no pod of the node is about to start, like one which is not managed
// by Kubernetes, is not waited for.
func TestFindProfileDoesNotWaitForUnknownContainers(t *testing.T) {
	t.Parallel()

	sut, _ := newClusterRecorder(true, false)
	watchPods(t, sut, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}))

	sut.containerLookupTimeout = time.Minute

	const unknown = "0000000000000000000000000000000000000000000000000000000000000003"

	start := time.Now()
	_, err := sut.findProfileForContainerID(unknown)
	require.ErrorIs(t, err, errContainerNotInCluster)
	require.Less(t, time.Since(start), 30*time.Second)
	require.True(t, sut.containersNotFound.Has(unknown))
}

// TestCacheProfilesOfUnresolvedContainers asserts that a container whose lookup
// gave up gets its profile once the pod status tells its ID.
func TestCacheProfilesOfUnresolvedContainers(t *testing.T) {
	t.Parallel()

	sut, _ := newClusterRecorder(true, false)

	// Without pods, like spoc.
	sut.cacheProfilesOfUnresolvedContainers()

	annotations := map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}

	creating := podWithContainer(annotations)
	creating.Status.ContainerStatuses[0].ContainerID = ""

	lw := watchPods(t, sut, creating)

	const key = 7

	sut.containerKeys.Insert(key, containerID)
	sut.containersNotFound.Set(containerID, struct{}{}, ttlcache.DefaultTTL)

	sut.cacheProfilesOfUnresolvedContainers()

	_, ok := sut.profileOfKey(key)
	require.False(t, ok)

	modifyPod(t, sut, lw, podWithContainer(annotations))

	sut.cacheProfilesOfUnresolvedContainers()

	got, ok := sut.profileOfKey(key)
	require.True(t, ok)
	require.Equal(t, profile, got)
}

// TestCacheProfilesOfPod asserts that the profiles of all recorded containers
// of a pod are cached, for seccomp and AppArmor.
func TestCacheProfilesOfPod(t *testing.T) {
	t.Parallel()

	const initContainerID = "0000000000000000000000000000000000000000000000000000000000000003"

	sut, _ := newClusterRecorder(true, true)

	p := podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr":   profile,
		config.ApparmorProfileRecordBpfAnnotationKey + "init": "apparmor-profile",
		config.SeccompProfileRecordBpfAnnotationKey + "none":  "",
	})
	p.Status.InitContainerStatuses = []v1.ContainerStatus{
		{Name: "init", ContainerID: "containerd://" + initContainerID},
		{Name: "none", ContainerID: "containerd://" + strings.Repeat("4", 64)},
	}

	sut.cacheProfilesOfPod(p)

	got, ok := sut.containerIDToProfileMap.Get(containerID)
	require.True(t, ok)
	require.Equal(t, profile, got)

	got, ok = sut.containerIDToProfileMap.Get(initContainerID)
	require.True(t, ok)
	require.Equal(t, "apparmor-profile", got)

	_, ok = sut.containerIDToProfileMap.Get(strings.Repeat("4", 64))
	require.False(t, ok)
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

	require.NoError(
		t,
		verifyProcess(42, 7, 0, time.Hour, startedAt(time.Minute), inMntns("mnt:[7]")),
	)

	// The time is not known.
	require.NoError(t, verifyProcess(42, 7, 0, 0, startedAt(time.Minute), inMntns("mnt:[7]")))

	err := verifyProcess(42, 7, 0, time.Minute, startedAt(time.Hour), inMntns("mnt:[7]"))
	require.ErrorIs(t, err, errProcessChanged)

	err = verifyProcess(42, 7, 0, time.Hour, startedAt(time.Minute), inMntns("mnt:[8]"))
	require.ErrorIs(t, err, errProcessChanged)

	err = verifyProcess(42, 7, 0, time.Hour, func(int) (time.Duration, error) {
		return 0, os.ErrNotExist
	}, inMntns("mnt:[7]"))
	require.ErrorIs(t, err, os.ErrNotExist)

	// The reported start time identifies the process without its mount
	// namespace, which a confined process may not let the recorder read.
	unreadable := func(string) (string, error) { return "", os.ErrPermission }
	reported := time.Minute + 5*time.Millisecond
	tick := util.ProcessStartTimeTick

	err = verifyProcess(42, 7, reported, 0, startedAt(time.Minute), unreadable)
	require.ErrorIs(t, err, errMntnsDenied)
	require.ErrorIs(t, err, os.ErrPermission)

	err = verifyProcess(42, 7, reported, 0, startedAt(time.Minute-tick), unreadable)
	require.ErrorIs(t, err, errProcessChanged)

	err = verifyProcess(42, 7, reported, 0, startedAt(time.Minute+tick), unreadable)
	require.ErrorIs(t, err, errProcessChanged)

	// A readable mount namespace is still checked, as the process may have
	// left it after it got reported.
	err = verifyProcess(42, 7, reported, 0, startedAt(time.Minute), inMntns("mnt:[8]"))
	require.ErrorIs(t, err, errProcessChanged)

	// Without the start time, the mount namespace has to be readable.
	err = verifyProcess(42, 7, 0, time.Hour, startedAt(time.Minute), unreadable)
	require.ErrorIs(t, err, os.ErrPermission)
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
		watchPods(t, sut, podWithContainer(map[string]string{
			config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
		}))

		sut.AppArmor.handleFileEvent(fileEvent(7, flagRead, "/etc/passwd"))

		sut.handleNewPidEvent(newPidEvent{
			pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load(),
		})

		require.Zero(t, sut.containerKeys.Size())
		require.Zero(t, mock.UpdateValue64CallCount(), "the key must not be excluded")
		require.Contains(t, sut.AppArmor.recordedFiles, recordingKey(7))
	}
}

// TestNewPidEventWithDeniedMntns asserts that a process whose start time
// matches is mapped although its mount namespace could not be read, as the
// AppArmor profile of a confined process denies it.
func TestNewPidEventWithDeniedMntns(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, true)
	sut.uniqueKeys = true

	mock.ContainerIDForPIDReturns(containerID, nil)
	mock.VerifyProcessReturns(fmt.Errorf("%w: %w", errMntnsDenied, os.ErrPermission))
	watchPods(t, sut, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}))

	for pid := range uint32(2) {
		sut.handleNewPidEvent(newPidEvent{
			pid:        42 + pid,
			mntns:      1,
			key:        7 + uint64(pid),
			generation: sut.recordingGeneration.Load(),
			startedAt:  time.Minute,
		})
	}

	require.ElementsMatch(t, []uint64{7, 8}, sut.containerKeys.Keys(containerID))
	require.Zero(t, mock.UpdateValue64CallCount(), "the keys must not be excluded")
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
	watchPods(t, sut, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}))

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
}

// TestNewPidEventExcludesCgroupWithoutContainer asserts that a key whose
// cgroup has no container is excluded right away, without looking up its
// process.
func TestNewPidEventExcludesCgroupWithoutContainer(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	sut.uniqueKeys = true
	sut.cgroupKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	mock.CgroupPathForIDReturns("/system.slice/sshd.service", nil)

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Zero(t, mock.ContainerIDForPIDCallCount())
	require.Zero(t, mock.VerifyProcessCallCount())
	require.Equal(t, 1, mock.UpdateValue64CallCount())
}

// TestNewPidEventOfMovedProcess asserts that a key whose cgroup has no
// container is not mapped to the container its process moved into, like the
// init process of the runtime does.
func TestNewPidEventOfMovedProcess(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	sut.uniqueKeys = true
	sut.cgroupKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	mock.CgroupPathForIDReturns("/system.slice/containerd.service", nil)
	mock.ContainerIDForPIDReturns(containerID, nil)
	watchPods(t, sut, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}))

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Zero(t, sut.containerKeys.Size())
	require.Zero(t, mock.ContainerIDForPIDCallCount())
}

// TestNewPidEventOfRemovedCgroup asserts that the key of a removed cgroup is
// not mapped to the container of its process, which moved out of the cgroup.
func TestNewPidEventOfRemovedCgroup(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(true, false)
	sut.uniqueKeys = true
	sut.cgroupKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	mock.CgroupPathForIDReturns("", fmt.Errorf("open cgroup 7: %w", syscall.ESTALE))
	mock.ContainerIDForPIDReturns(containerID, nil)
	watchPods(t, sut, podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	}))

	sut.handleNewPidEvent(
		newPidEvent{pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load()},
	)

	require.Zero(t, sut.containerKeys.Size())
	require.Zero(t, mock.ContainerIDForPIDCallCount())
	require.Zero(t, mock.UpdateValue64CallCount(), "the key must not be excluded")
}

// TestNewPidEventFallsBackToPid asserts that a cgroup which cannot be
// resolved, like one outside of the cgroup namespace of the recorder, is left
// to the lookup by PID, which verifies the process with its start time and
// mount namespace before it excludes the key.
func TestNewPidEventFallsBackToPid(t *testing.T) {
	t.Parallel()

	for _, cgroupErr := range []error{os.ErrPermission, errCgroupNotVisible} {
		t.Run(cgroupErr.Error(), func(t *testing.T) {
			t.Parallel()

			sut, mock := newClusterRecorder(true, false)
			sut.uniqueKeys = true
			sut.cgroupKeys = true
			sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

			mock.CgroupPathForIDReturns("", cgroupErr)
			mock.ContainerIDForPIDReturns("", util.ErrContainerIDNotFound)

			sut.handleNewPidEvent(newPidEvent{
				pid: 42, mntns: 1, key: 7, generation: sut.recordingGeneration.Load(),
				startedAt: time.Minute, seenAt: time.Hour,
			})

			require.Equal(t, 1, mock.ContainerIDForPIDCallCount())
			require.Equal(t, 1, mock.VerifyProcessCallCount())
			require.Equal(t, 1, mock.UpdateValue64CallCount())

			pid, mntns, startedAt, seenAt := mock.VerifyProcessArgsForCall(0)
			require.Equal(t, uint32(42), pid)
			require.Equal(t, uint32(1), mntns)
			require.Equal(t, time.Minute, startedAt)
			require.Equal(t, time.Hour, seenAt)
		})
	}
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

	sut.scheduleNewPidEvent(42, 1, 7, 0)
	sut.scheduleNewPidEvent(42, 1, 7, 0)

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
	// A container which is not in the cluster.
	sut.containerKeys.Insert(stale, "unknown")

	mock.MapKeysReturns([][]byte{pidKey(100, alive), pidKey(200, stale)}, nil)
	mock.StatCalls(func(path string) (os.FileInfo, error) {
		if path == "/proc/100/stat" {
			return os.Stat("/")
		}

		return nil, os.ErrNotExist
	})

	sut.sweepStaleKeys()
	require.ElementsMatch(t, []uint64{mapped, alive, stale}, sut.AppArmor.GetKnownKeys())

	sut.sweepStaleKeys()
	require.ElementsMatch(t, []uint64{mapped, alive}, sut.AppArmor.GetKnownKeys())
	require.Empty(t, sut.staleKeys)

	_, found := sut.containerKeys.Get(stale)
	require.False(t, found)

	_, found = sut.containerKeys.Get(mapped)
	require.True(t, found)
}

// TestPruneExcludedKeys asserts that excluded cgroups which are gone get
// removed from the kernel map, while the ones still around stay excluded.
func TestPruneExcludedKeys(t *testing.T) {
	t.Parallel()

	sut, mock := newClusterRecorder(false, true)
	sut.cgroupKeys = true
	sut.excludeKeysBpfMap = &libbpfgo.BPFMap{}

	const (
		gone  uint64 = 1
		alive uint64 = 2
	)

	sut.AppArmor.Exclude(gone)
	sut.AppArmor.Exclude(alive)

	key := func(k uint64) []byte {
		return binary.NativeEndian.AppendUint64(nil, k)
	}

	const hidden uint64 = 3

	sut.AppArmor.Exclude(hidden)
	mock.MapKeysReturns([][]byte{key(gone), key(alive), key(hidden)}, nil)
	mock.CgroupRemovedCalls(func(id uint64) (bool, error) {
		switch id {
		case alive:
			return false, nil
		case hidden:
			// A cgroup outside of the cgroup namespace of the daemon is not
			// known to be gone.
			return false, syscall.EPERM
		default:
			return true, nil
		}
	})

	sut.pruneExcludedKeys(sut.recordingGeneration.Load())

	require.Equal(t, 1, mock.DeleteKey64CallCount())
	_, deleted := mock.DeleteKey64ArgsForCall(0)
	require.Equal(t, gone, deleted)
	require.False(t, sut.AppArmor.isExcluded(gone))
	require.True(t, sut.AppArmor.isExcluded(alive))
	require.True(t, sut.AppArmor.isExcluded(hidden))
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

	sut, _ := newRecordingRecorder(t, false, false)
	sut.clientset = &kubernetes.Clientset{}
	sut.now = func() time.Time { return now }

	// Nothing is released before the pods are known.
	lw := podindextest.New()

	idx, err := podindex.New(lw)
	require.NoError(t, err)

	sut.pods = idx

	sut.releaseAbandonedRecording()

	now = now.Add(uncollectedRecordingTimeout)

	sut.releaseAbandonedRecording()
	require.EqualValues(t, 1, atomic.LoadInt64(&sut.startRequests))

	// A Stop got lost.
	_, err = sut.Start(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)

	recorded := podWithContainer(map[string]string{
		config.SeccompProfileRecordBpfAnnotationKey + "ctr": profile,
	})
	lw = watchPods(t, sut, recorded)

	now = now.Add(time.Hour)

	sut.releaseAbandonedRecording()
	require.EqualValues(t, 2, atomic.LoadInt64(&sut.startRequests))

	modifyPod(t, sut, lw, podWithContainer(nil))

	sut.releaseAbandonedRecording()

	now = now.Add(abandonedRecordingTimeout / 2)

	sut.releaseAbandonedRecording()
	require.EqualValues(t, 2, atomic.LoadInt64(&sut.startRequests))

	// A new recording starts the wait over.
	_, err = sut.Start(t.Context(), &api.EmptyRequest{})
	require.NoError(t, err)

	now = now.Add(abandonedRecordingTimeout)

	sut.releaseAbandonedRecording()
	require.EqualValues(t, 3, atomic.LoadInt64(&sut.startRequests))

	now = now.Add(abandonedRecordingTimeout)

	sut.releaseAbandonedRecording()
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

	sut, _ := newRecordingRecorder(t, false, false)
	sut.clientset = &kubernetes.Clientset{}
	sut.now = func() time.Time { return now }

	watchPods(t, sut, podWithContainer(nil))
	sut.containerIDToProfileMap.Insert(containerID, profile)

	sut.releaseAbandonedRecording()

	now = now.Add(abandonedRecordingTimeout)

	sut.releaseAbandonedRecording()
	require.EqualValues(t, 1, atomic.LoadInt64(&sut.startRequests))

	now = now.Add(uncollectedRecordingTimeout)

	sut.releaseAbandonedRecording()
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
