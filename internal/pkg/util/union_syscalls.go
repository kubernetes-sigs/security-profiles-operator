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
	"github.com/saschagrunert/security-profiles-merger/seccomp"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func UnionSyscalls(syscalls, appliedSyscalls []seccompprofile.Syscall) ([]seccompprofile.Syscall, error) {
	left := syscallsToOCI(syscalls)
	right := syscallsToOCI(appliedSyscalls)
	merged := seccomp.UnionSyscalls(left, right)

	return syscallsFromOCI(merged), nil
}
