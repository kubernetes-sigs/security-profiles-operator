//go:build linux

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

package enricher

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// auditArches maps the audit architectures (AUDIT_ARCH_* in
// include/uapi/linux/audit.h) to the libseccomp ones.
var auditArches = map[string]seccomp.ScmpArch{
	"40000003": seccomp.ArchX86,
	"c000003e": seccomp.ArchAMD64,
	"40000028": seccomp.ArchARM,
	"c00000b7": seccomp.ArchARM64,
	"80000015": seccomp.ArchPPC64,
	"c0000015": seccomp.ArchPPC64LE,
	// The kernel prints the architecture without leading zeros.
	"16":       seccomp.ArchS390,
	"80000016": seccomp.ArchS390X,
	"c00000f3": seccomp.ArchRISCV64,
}

// nativeAuditArches maps the Go architectures to their audit architecture.
var nativeAuditArches = map[string]string{
	"386":     "40000003",
	"amd64":   "c000003e",
	"arm":     "40000028",
	"arm64":   "c00000b7",
	"ppc64":   "80000015",
	"ppc64le": "c0000015",
	"s390x":   "80000016",
	"riscv64": "c00000f3",
}

// syscallName returns the syscall name for the provided ID. arch is the audit
// architecture of the syscall, the syscall numbers differ between them. An
// empty or unknown arch resolves the ID for the native architecture.
func syscallName(id int32, arch string) (string, error) {
	scmpArch, known := auditArches[arch]
	if !known {
		arch = ""
	}

	key := syscallKey{id: id, arch: arch}
	if name, ok := syscallNames.Load(key); ok {
		if s, isString := name.(string); isString {
			return s, nil
		}
	}

	var (
		name string
		err  error
	)

	if known {
		name, err = seccomp.ScmpSyscall(id).GetNameByArch(scmpArch)
	} else {
		name, err = seccomp.ScmpSyscall(id).GetName()
	}

	if err != nil {
		return "", err
	}

	// Only the names which exist are cached, which bounds the cache by the
	// syscalls of the known architectures.
	syscallNames.Store(key, name)

	return name, nil
}

// syscallKey is the key of a syscall in syscallNames. The architecture is
// empty for the native one.
type syscallKey struct {
	id   int32
	arch string
}

// syscallNames caches the names syscallName resolved, which is a call into
// libseccomp for every audit line otherwise.
var syscallNames sync.Map

// isNativeArch reports whether arch is the audit architecture of the native
// syscalls. Syscalls of a compat architecture, like 32-bit x86 programs on
// amd64, cannot be allowed by a recorded profile, which only covers the
// native one.
func isNativeArch(arch string) bool {
	native, ok := nativeAuditArches[runtime.GOARCH]

	return arch == "" || !ok || arch == native
}

// isKnownArch reports whether arch is one of the audit architectures.
func isKnownArch(arch string) bool {
	_, known := auditArches[arch]

	return known
}

// uptime returns the time since boot, like the start times of processes.
func uptime() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, fmt.Errorf("get boot time: %w", err)
	}

	return time.Duration(ts.Nano()), nil
}
