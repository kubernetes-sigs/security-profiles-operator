/*
Copyright 2022 The Kubernetes Authors.

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

package util

import (
	"sort"

	"github.com/containers/common/pkg/seccomp"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

func UnionSyscalls(baseSyscalls, appliedSyscalls []*seccompprofile.Syscall) []*seccompprofile.Syscall {
	longestLen := len(baseSyscalls)
	if len(appliedSyscalls) > longestLen {
		longestLen = len(appliedSyscalls)
	}

	allSyscalls := make(map[seccomp.Action]map[string]bool, longestLen)
	for _, b := range baseSyscalls {
		allSyscalls[b.Action] = make(map[string]bool)
		for _, n := range b.Names {
			allSyscalls[b.Action][n] = true
		}
	}
	for _, s := range appliedSyscalls {
		if _, ok := allSyscalls[s.Action]; !ok {
			allSyscalls[s.Action] = make(map[string]bool)
		}
		for _, n := range s.Names {
			allSyscalls[s.Action][n] = true
		}
	}
	finalSyscalls := make([]*seccompprofile.Syscall, 0, longestLen)
	for action, names := range allSyscalls {
		syscall := seccompprofile.Syscall{
			Action: action,
		}
		for n := range names {
			syscall.Names = append(syscall.Names, n)
		}
		sort.Strings(syscall.Names)
		finalSyscalls = append(finalSyscalls, &syscall)
	}
	return finalSyscalls
}
