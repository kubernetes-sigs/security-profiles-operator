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
	"fmt"
	"sort"

	"github.com/imdario/mergo"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

func UnionSyscalls(syscalls, appliedSyscalls []*seccompprofile.Syscall) ([]*seccompprofile.Syscall, error) {
	if err := mergo.Merge(
		&syscalls,
		appliedSyscalls,
		mergo.WithAppendSlice,
		mergo.WithSliceDeepCopy,
		mergo.WithOverrideEmptySlice,
		mergo.WithOverwriteWithEmptyValue,
	); err != nil {
		return nil, fmt.Errorf("merge syscalls: %w", err)
	}

	for _, syscall := range syscalls {
		sort.Strings(syscall.Names)
	}

	sort.Slice(syscalls, func(i, j int) bool {
		return syscalls[i].Action < syscalls[j].Action
	})

	return syscalls, nil
}
