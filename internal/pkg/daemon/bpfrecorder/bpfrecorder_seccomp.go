//go:build linux && !no_bpf
// +build linux,!no_bpf

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

package bpfrecorder

import (
	"fmt"
	"sort"
	"strconv"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	seccomp "github.com/seccomp/libseccomp-golang"
)

type SeccompRecorder struct {
	logger               logr.Logger
	syscalls             *bpf.BPFMap
	syscallIDtoNameCache map[string]string
}

func newSeccompRecorder(logger logr.Logger) *SeccompRecorder {
	return &SeccompRecorder{
		logger:               logger,
		syscallIDtoNameCache: make(map[string]string),
	}
}

func (s *SeccompRecorder) Load(b *BpfRecorder) error {
	s.logger.Info("Getting syscalls map")
	syscalls, err := b.GetMap(b.module, "mntns_syscalls")
	if err != nil {
		return fmt.Errorf("get syscalls map: %w", err)
	}
	s.syscalls = syscalls
	return nil
}

func (s *SeccompRecorder) Unload() {
	s.syscalls = nil
}

func (s *SeccompRecorder) PopSyscalls(b *BpfRecorder, mntns uint32) ([]string, error) {
	syscalls, err := b.GetValue(s.syscalls, mntns)
	if err != nil {
		s.logger.Error(err, "No syscalls found for mntns", "mntns", mntns)
		return nil, fmt.Errorf("no syscalls found for mntns: %d", mntns)
	}
	syscallNames := s.convertSyscallIDsToNames(b, syscalls)

	if err := b.DeleteKey(b.Seccomp.syscalls, mntns); err != nil {
		s.logger.Error(err, "Unable to cleanup syscalls map", "mntns", mntns)
	}

	return sortUnique(syscallNames), nil
}

func sortUnique(input []string) (result []string) {
	tmp := map[string]bool{}
	for _, val := range input {
		tmp[val] = true
	}
	for k := range tmp {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

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
	item, ok := s.syscallIDtoNameCache[key]
	if ok {
		return item, nil
	}

	name, err := b.GetName(seccomp.ScmpSyscall(id))
	if err != nil {
		return "", fmt.Errorf("get syscall name for ID %d: %w", id, err)
	}

	s.syscallIDtoNameCache[key] = name
	return name, nil
}
