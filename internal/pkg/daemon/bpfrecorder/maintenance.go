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
				b.cacheProfilesOfUnresolvedContainers(ctx)
			}

			b.sweepStaleKeys()
			b.releaseAbandonedRecording(ctx)
		}
	}
}

// sweepStaleKeys drops the data recorded under keys which no recorded container
// got found for and whose processes are gone. Nobody can collect that data, but it
// would take up room in the maps until the recording stops, which may never
// happen on a node which always records something.
func (b *BpfRecorder) sweepStaleKeys() {
	if b.clientset == nil || atomic.LoadInt64(&b.startRequests) == 0 {
		clear(b.staleKeys)

		return
	}

	// StopRecording clears everything anyway, holding the write lock.
	b.attachUnattachMutex.RLock()
	defer b.attachUnattachMutex.RUnlock()

	alive := b.keysWithProcesses()
	if alive == nil {
		// The processes are unknown, so no key is known to be without any.
		return
	}

	stale := make(map[uint64]int, len(b.staleKeys))

	for _, key := range b.recordedKeys() {
		if _, recorded := b.profileOfKey(key); recorded {
			continue
		}

		if _, ok := alive[key]; ok {
			continue
		}

		// A cgroup can get new processes as long as it exists.
		if b.cgroupKeys {
			if _, err := b.CgroupPathForID(key); err == nil {
				continue
			}
		}

		sweeps := b.staleKeys[key] + 1
		if sweeps < staleKeySweeps {
			stale[key] = sweeps

			continue
		}

		b.logger.V(config.VerboseLevel).
			Info("Dropping data of a workload without container", "key", key)

		if b.Seccomp != nil {
			b.Seccomp.Clear(b, []uint64{key})
		}

		if b.AppArmor != nil {
			b.AppArmor.Clear([]uint64{key})
		}
	}

	b.staleKeys = stale
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

// keysWithProcesses returns the keys of the processes of the active_pids map
// which still exist. A PID which got reused keeps its key here, which only
// delays dropping its data.
func (b *BpfRecorder) keysWithProcesses() map[uint64]struct{} {
	alive := map[uint64]struct{}{}

	if b.activePidsBpfMap == nil {
		return alive
	}

	raw, err := b.MapKeys(b.activePidsBpfMap)
	if err != nil {
		b.logger.Error(err, "Unable to list recorded processes")

		// Nothing is known to be gone.
		return nil
	}

	for _, entry := range raw {
		// struct pid_key of recorder.bpf.c.
		if len(entry) != 16 {
			continue
		}

		pid := binary.NativeEndian.Uint32(entry[0:4])
		key := binary.NativeEndian.Uint64(entry[8:16])

		if _, ok := alive[key]; ok {
			continue
		}

		if _, err := b.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10)); err == nil {
			alive[key] = struct{}{}
		}
	}

	return alive
}

// releaseAbandonedRecording stops a recording once no pod on the node asked for
// one for a while. Start and Stop are counted, and a Start which the client
// retried or whose Stop got lost, for example because the client restarted,
// would keep the hooks attached for the lifetime of the recorder.
func (b *BpfRecorder) releaseAbandonedRecording(ctx context.Context) {
	if b.clientset == nil {
		return
	}

	if atomic.LoadInt64(&b.startRequests) == 0 {
		b.startMu.Lock()
		b.idleSince = time.Time{}
		b.startMu.Unlock()

		return
	}

	listCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	pods, err := b.ListPods(listCtx, b.clientset, b.nodeName)
	if err != nil {
		b.logger.Error(err, "Unable to list pods to check for recorded ones")

		return
	}

	recorded := false

	if pods != nil {
		for i := range pods.Items {
			if recordsBpf(&pods.Items[i]) {
				recorded = true

				break
			}
		}
	}

	b.startMu.Lock()
	defer b.startMu.Unlock()

	now := b.now()

	if recorded {
		b.idleSince = time.Time{}

		return
	}

	// A Start after the node became idle belongs to a pod the list above may
	// have missed.
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
