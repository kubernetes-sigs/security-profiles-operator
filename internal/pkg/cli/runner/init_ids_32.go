//go:build linux && (386 || arm)

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

package runner

import "golang.org/x/sys/unix"

// The syscalls to drop privileges, in the variants taking 32 bit IDs. They
// are the ones Go uses for exec.Cmd credentials, so a profile recorded by spoc
// allows them.
const (
	sysSetgroups = unix.SYS_SETGROUPS32
	sysSetgid    = unix.SYS_SETGID32
	sysSetuid    = unix.SYS_SETUID32
)
