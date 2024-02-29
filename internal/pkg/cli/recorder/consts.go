/*
Copyright 2023 The Kubernetes Authors.

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

package recorder

import "sigs.k8s.io/security-profiles-operator/internal/pkg/cli"

const (
	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = cli.FlagOutputFile

	// FlagType is the flag for defining the recorder type.
	FlagType string = "type"

	// FlagBaseSyscalls are the syscalls included in every seccomp profile to
	// ensure compatibility with OCI runtimes like runc and crun.
	FlagBaseSyscalls string = "base-syscalls"

	// FlagNoBaseSyscalls can be used to indicate that no base syscalls should
	// be added at all.
	FlagNoBaseSyscalls string = "no-base-syscalls"

	// FlagNoStart can be used to indicate that the target process is managed
	// externally and should not be started.
	FlagNoStart string = "no-start"
)

// Type is the enum for all available recorder types.
type Type string

const (
	// TypeSeccomp is the type indicating that we should record a seccomp CRD
	// profile.
	TypeSeccomp Type = "seccomp"

	// TypeRawSeccomp is the type indicating that we should record a raw
	// seccomp JSON profile.
	TypeRawSeccomp Type = "raw-seccomp"

	// TypeApparmor is the type indicating that we should record an apparmor CRD
	// profile.
	TypeApparmor Type = "apparmor"

	// TypeRawAppArmor is the type indicating that we should record a raw
	// apparmor JSON profile.
	TypeRawAppArmor Type = "raw-apparmor"
)

var (
	// DefaultOutputFile defines the default output location for the recorder.
	DefaultOutputFile = cli.DefaultFile

	// DefaultBaseSyscalls are the syscalls included in every seccomp profile
	// to ensure compatibility with OCI runtimes like runc and crun.
	//
	// Please note that the syscalls may vary depending on which container
	// runtime we choose.
	DefaultBaseSyscalls = []string{
		"access",
		"arch_prctl",
		"brk",
		"capget",
		"capset",
		"chdir",
		"chmod",
		"chown",
		"clone",
		"close",
		"close_range",
		"dup2",
		"dup3",
		"epoll_create1",
		"epoll_ctl",
		"epoll_pwait",
		"execve",
		"exit_group",
		"faccessat2",
		"fchdir",
		"fchmodat",
		"fchown",
		"fchownat",
		"fcntl",
		"fstat",
		"fstatfs",
		"futex",
		"getdents64",
		"getegid",
		"geteuid",
		"getgid",
		"getpid",
		"getppid",
		"gettid",
		"getuid",
		"ioctl",
		"keyctl",
		"lseek",
		"mkdirat",
		"mknodat",
		"mmap",
		"mount",
		"mprotect",
		"munmap",
		"nanosleep",
		"newfstatat",
		"openat",
		"openat2",
		"pipe2",
		"pivot_root",
		"prctl",
		"pread64",
		"pselect6",
		"read",
		"readlink",
		"readlinkat",
		"rt_sigaction",
		"rt_sigprocmask",
		"rt_sigreturn",
		"sched_getaffinity",
		"sched_yield",
		"seccomp",
		"set_robust_list",
		"set_tid_address",
		"setgid",
		"setgroups",
		"sethostname",
		"setns",
		"setresgid",
		"setresuid",
		"setsid",
		"setuid",
		"sigaltstack",
		"statfs",
		"statx",
		"symlinkat",
		"tgkill",
		"umask",
		"umount2",
		"unlinkat",
		"unshare",
		"utimensat",
		"write",
	}
)
