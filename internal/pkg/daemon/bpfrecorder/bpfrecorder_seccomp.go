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
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	seccomp "github.com/seccomp/libseccomp-golang"
)

type SeccompRecorder struct {
	logger   logr.Logger
	syscalls *bpf.BPFMap
	// syscallIDtoNameCacheMutex guards syscallIDtoNameCache. PopSyscalls runs
	// from the SyscallsForProfile gRPC handler, which holds only a read lock on
	// the recorder, so concurrent calls would otherwise write the map at once.
	syscallIDtoNameCacheMutex sync.RWMutex
	syscallIDtoNameCache      map[string]string
}

func newSeccompRecorder(logger logr.Logger) *SeccompRecorder {
	return &SeccompRecorder{
		logger:               logger,
		syscallIDtoNameCache: make(map[string]string),
	}
}

func (s *SeccompRecorder) Load(b *BpfRecorder) error {
	s.logger.Info("Getting syscalls map")

	syscalls, err := b.GetMap(b.module, mapRecordedSyscalls)
	if err != nil {
		return fmt.Errorf("get syscalls map: %w", err)
	}

	s.syscalls = syscalls

	return nil
}

func (s *SeccompRecorder) StartRecording(b *BpfRecorder) error {
	// This uses one of the base hooks, no need to attach here.
	return nil
}

func (s *SeccompRecorder) StopRecording(b *BpfRecorder) error {
	if err := clearBpfMap(b, s.syscalls); err != nil {
		return fmt.Errorf("failed to clean up syscalls map: %w", err)
	}

	return nil
}

// Syscalls returns the names of the syscalls recorded for keys. The data stays
// in the map until Clear is called. It fails with errIncompleteRead if the
// syscalls of a key could not be read, unless allowPartial is set: then it
// returns the syscalls of the other keys and reports them as incomplete.
func (s *SeccompRecorder) Syscalls(
	b *BpfRecorder, keys []uint64, allowPartial bool,
) (syscalls []string, incomplete bool, err error) {
	var (
		merged  []byte
		lastErr error
	)

	for _, key := range keys {
		recorded, err := b.GetValue64(s.syscalls, key)
		if err != nil {
			if !errors.Is(err, syscall.ENOENT) {
				s.logger.Error(err, "Unable to read syscalls", "key", key)
				lastErr = err
			}

			continue
		}

		if merged == nil {
			merged = make([]byte, len(recorded))
		}

		for id, set := range recorded {
			if set == 1 && id < len(merged) {
				merged[id] = 1
			}
		}
	}

	// The syscalls of the keys which were read are not the complete profile,
	// which would be stored and the data of all keys dropped afterwards. The
	// collection is retried instead, until the caller accepts partial data.
	if lastErr != nil && (!allowPartial || merged == nil) {
		return nil, false, fmt.Errorf("%w: %w", errIncompleteRead, lastErr)
	}

	if merged == nil {
		// Nothing was recorded, which is not going to change on a retry.
		return nil, false, ErrNotFound
	}

	return sortUnique(s.convertSyscallIDsToNames(b, merged)), lastErr != nil, nil
}

// Clear drops the syscalls recorded for keys.
func (s *SeccompRecorder) Clear(b *BpfRecorder, keys []uint64) {
	for _, key := range keys {
		if err := b.DeleteKey64(s.syscalls, key); err != nil && !errors.Is(err, syscall.ENOENT) {
			s.logger.Error(err, "Unable to cleanup syscalls map", "key", key)
		}
	}
}

func sortUnique(input []string) []string {
	slices.Sort(input)

	return slices.Compact(input)
}

// convertSyscallIDsToNames resolves the IDs with the native architecture. The
// BPF program leaves out the syscalls of 32 bit tasks, whose numbers belong to
// another architecture, so a profile of a 32 bit program is incomplete.
func (s *SeccompRecorder) convertSyscallIDsToNames(b *BpfRecorder, syscalls []byte) []string {
	result := []string{}

	for id, set := range syscalls {
		if set == 1 {
			name, err := s.syscallNameForID(b, id)
			if err != nil {
				s.logger.Error(err, "unable to convert syscall ID", "id", id)

				continue
			}

			result = append(result, name)
		}
	}

	return result
}

func (s *SeccompRecorder) syscallNameForID(b *BpfRecorder, id int) (string, error) {
	key := strconv.Itoa(id)

	s.syscallIDtoNameCacheMutex.RLock()
	item, ok := s.syscallIDtoNameCache[key]
	s.syscallIDtoNameCacheMutex.RUnlock()

	if ok {
		return item, nil
	}

	name, err := b.GetName(seccomp.ScmpSyscall(id))
	if err != nil {
		return "", fmt.Errorf("get syscall name for ID %d: %w", id, err)
	}

	s.syscallIDtoNameCacheMutex.Lock()
	s.syscallIDtoNameCache[key] = name
	s.syscallIDtoNameCacheMutex.Unlock()

	return name, nil
}
