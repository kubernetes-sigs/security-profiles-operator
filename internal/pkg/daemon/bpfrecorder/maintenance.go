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
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// runMaintenance periodically drops what nobody is going to collect while a
// recording is running.
func (b *BpfRecorder) runMaintenance(ctx context.Context) {
	ticker := time.NewTicker(maintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt64(&b.startRequests) > 0 {
				b.cacheProfilesOfUnresolvedContainers()
			}

			b.sweepStaleKeys()
			b.releaseAbandonedRecording()
		}
	}
}

// sweepStaleKeys drops the data recorded under keys which no recorded container
// got found for and whose processes are gone. Nobody can collect that data, but it
// would take up room in the maps until the recording stops, which may never
// happen on a node which always records something.
//
// Looking up the processes and cgroups of up to every recorded key takes a
// while, so it runs without the lock, which would hold off StopRecording and
// the collection of profiles in the meantime. Only reading the maps and
// dropping the data take it.
func (b *BpfRecorder) sweepStaleKeys() {
	if b.clientset == nil || atomic.LoadInt64(&b.startRequests) == 0 {
		clear(b.staleKeys)

		return
	}

	b.attachUnattachMutex.RLock()
	generation := b.recordingGeneration.Load()
	recorded := b.recordedKeys()
	pids, err := b.recordedPids()
	b.attachUnattachMutex.RUnlock()

	if err != nil {
		// The processes are unknown, so no key is known to be without any.
		b.logger.Error(err, "Unable to list recorded processes")

		return
	}

	alive := b.keysWithProcesses(pids)
	stale := make(map[uint64]int, len(b.staleKeys))

	var drop []uint64

	for _, key := range recorded {
		if !b.isStaleKey(key, alive) {
			continue
		}

		sweeps := b.staleKeys[key] + 1
		if sweeps < staleKeySweeps {
			stale[key] = sweeps

			continue
		}

		drop = append(drop, key)
	}

	b.staleKeys = stale

	b.pruneExcludedKeys(generation)

	if len(drop) == 0 {
		return
	}

	// StopRecording clears everything anyway, holding the write lock.
	b.attachUnattachMutex.RLock()
	defer b.attachUnattachMutex.RUnlock()

	if b.recordingGeneration.Load() != generation {
		return
	}

	for _, key := range drop {
		// The container of the key may have been found in the meantime.
		if _, recorded := b.profileOfKey(key); recorded {
			continue
		}

		b.logger.V(config.VerboseLevel).
			Info("Dropping data of a workload without container", "key", key)

		// Containers unknown to the cluster stay mapped until they are gone,
		// so that their keys do not pile up during a long recording.
		b.containerKeys.Delete(key)

		if b.Seccomp != nil {
			b.Seccomp.Clear(b, []uint64{key})
		}

		if b.AppArmor != nil {
			b.AppArmor.Clear([]uint64{key})
		}
	}
}

// pruneExcludedKeys forgets the excluded workloads whose cgroup is gone.
// Cgroup IDs are never reused, but every excluded one stays in the kernel map
// otherwise, which fills up during a long recording. With other keys, an
// excluded workload is only known to be gone once the session ends.
func (b *BpfRecorder) pruneExcludedKeys(generation uint64) {
	if !b.cgroupKeys {
		return
	}

	// Close frees the map under the write lock, so it is listed under the
	// read lock.
	b.attachUnattachMutex.RLock()

	if b.excludeKeysBpfMap == nil {
		b.attachUnattachMutex.RUnlock()

		return
	}

	raw, err := b.MapKeys(b.excludeKeysBpfMap)
	b.attachUnattachMutex.RUnlock()

	if err != nil {
		b.logger.Error(err, "Unable to list excluded workloads")

		return
	}

	var gone []uint64

	for _, k := range raw {
		if len(k) != 8 {
			continue
		}

		// Only a removed cgroup is gone. Other errors, like a cgroup outside
		// of the cgroup namespace of the daemon, tell nothing about it.
		key := binary.NativeEndian.Uint64(k)

		removed, err := b.CgroupRemoved(key)
		if err != nil {
			b.logger.V(config.VerboseLevel).Info(
				"Unable to check the cgroup of an excluded workload", "key", key, "error", err.Error(),
			)

			continue
		}

		if removed {
			gone = append(gone, key)
		}
	}

	if len(gone) == 0 {
		return
	}

	b.attachUnattachMutex.RLock()
	defer b.attachUnattachMutex.RUnlock()

	if b.recordingGeneration.Load() != generation || b.excludeKeysBpfMap == nil {
		return
	}

	for _, key := range gone {
		if err := b.DeleteKey64(b.excludeKeysBpfMap, key); err != nil {
			b.logger.Error(err, "Unable to forget excluded workload", "key", key)

			continue
		}

		if b.AppArmor != nil {
			b.AppArmor.Unexclude(key)
		}
	}
}

// isStaleKey reports whether the key has no recorded container and no
// processes, nor a cgroup which can get new processes.
func (b *BpfRecorder) isStaleKey(key uint64, alive map[uint64]struct{}) bool {
	if _, recorded := b.profileOfKey(key); recorded {
		return false
	}

	if _, ok := alive[key]; ok {
		return false
	}

	if b.cgroupKeys {
		if _, err := b.CgroupPathForID(key); err == nil {
			return false
		}
	}

	return true
}

// recordedKeys returns the keys data is recorded for, each one once, as a
// workload may be recorded for seccomp and AppArmor at the same time.
func (b *BpfRecorder) recordedKeys() []uint64 {
	var keys []uint64

	if b.Seccomp != nil && b.Seccomp.syscalls != nil {
		raw, err := b.MapKeys(b.Seccomp.syscalls)
		if err != nil {
			b.logger.Error(err, "Unable to list recorded workloads")
		}

		for _, key := range raw {
			if len(key) == 8 {
				keys = append(keys, binary.NativeEndian.Uint64(key))
			}
		}
	}

	if b.AppArmor != nil {
		keys = append(keys, b.AppArmor.GetKnownKeys()...)
	}

	slices.Sort(keys)

	return slices.Compact(keys)
}

// recordedPids returns the entries of the active_pids map, the recorded
// processes together with their keys.
func (b *BpfRecorder) recordedPids() ([][]byte, error) {
	if b.activePidsBpfMap == nil {
		return nil, nil
	}

	raw, err := b.MapKeys(b.activePidsBpfMap)
	if err != nil {
		return nil, fmt.Errorf("list active pids: %w", err)
	}

	return raw, nil
}

// keysWithProcesses returns the keys of the entries of the active_pids map
// whose process still exists. A PID which got reused keeps its key here, which
// only delays dropping its data.
func (b *BpfRecorder) keysWithProcesses(pids [][]byte) map[uint64]struct{} {
	alive := map[uint64]struct{}{}

	for _, entry := range pids {
		// struct pid_key of recorder.bpf.c.
		if len(entry) != 16 {
			continue
		}

		pid := binary.NativeEndian.Uint32(entry[0:4])
		key := binary.NativeEndian.Uint64(entry[8:16])

		if _, ok := alive[key]; ok {
			continue
		}

		// The stat file, which the AppArmor profile of the recorder allows
		// to read, unlike the directory of the process.
		if _, err := b.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat"); err == nil {
			alive[key] = struct{}{}
		}
	}

	return alive
}

// releaseAbandonedRecording stops a recording once no pod on the node asked for
// one for a while. Start and Stop are counted, and a Start which the client
// retried or whose Stop got lost, for example because the client restarted,
// would keep the hooks attached for the lifetime of the recorder.
func (b *BpfRecorder) releaseAbandonedRecording() {
	// Without the initial list every node looks idle.
	if b.pods == nil || !b.pods.HasSynced() {
		return
	}

	if atomic.LoadInt64(&b.startRequests) == 0 {
		b.startMu.Lock()
		b.idleSince = time.Time{}
		b.startMu.Unlock()

		return
	}

	recorded := slices.ContainsFunc(b.pods.Pods(), recordsBpf)

	b.startMu.Lock()
	defer b.startMu.Unlock()

	now := b.now()

	if recorded {
		b.idleSince = time.Time{}

		return
	}

	// A Start after the node became idle belongs to a pod the watch may not
	// have told yet.
	if b.idleSince.IsZero() || b.lastStart.After(b.idleSince) {
		b.idleSince = now

		return
	}

	timeout := abandonedRecordingTimeout
	if b.containerIDToProfileMap.Size() > 0 {
		timeout = uncollectedRecordingTimeout
	}

	if now.Sub(b.idleSince) < timeout {
		return
	}

	b.logger.Info(
		"Stopping the recording, no pod on the node is recorded any more",
		"startRequests", atomic.LoadInt64(&b.startRequests),
		"idleSince", b.idleSince,
	)

	b.idleSince = time.Time{}

	if err := b.StopRecording(); err != nil {
		b.logger.Error(err, "Unable to stop abandoned recording")

		return
	}

	atomic.StoreInt64(&b.startRequests, 0)
}

// recordsBpf reports whether a pod asks for a recording by the BPF recorder.
func recordsBpf(pod *v1.Pod) bool {
	if pod.Status.Phase == v1.PodSucceeded || pod.Status.Phase == v1.PodFailed {
		// The profiles of finished pods are collected right away.
		return false
	}

	for key, value := range pod.Annotations {
		if value == "" {
			continue
		}

		if strings.HasPrefix(key, config.SeccompProfileRecordBpfAnnotationKey) ||
			strings.HasPrefix(key, config.ApparmorProfileRecordBpfAnnotationKey) {
			return true
		}
	}

	return false
}
