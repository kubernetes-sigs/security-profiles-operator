//go:build linux && seccomp

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

package seccompprofile

import "golang.org/x/sys/unix"

// builtWithSeccomp reports whether the operator got built with seccomp
// support, which tells whether a node without seccomp lacks it for sure.
const builtWithSeccomp = true

// kernelSupportsSeccomp returns true if the kernel got configured with
// CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER. Without them, prctl(2) fails with
// EINVAL. With them, copying the NULL filter fails with EFAULT before any
// privilege check, so that no filter gets installed.
func kernelSupportsSeccomp() bool {
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, 0, 0, 0) != unix.EINVAL
}
