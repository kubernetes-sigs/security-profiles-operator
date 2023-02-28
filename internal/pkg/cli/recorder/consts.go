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

import (
	"os"
	"path/filepath"
)

const (
	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = "output-file"

	// FlagType is the flag for defining the recorder type.
	FlagType string = "type"

	// FlagBaseSyscalls are the syscalls included in every seccomp profile to
	// ensure compatibility with OCI runtimes like runc and crun.
	FlagBaseSyscalls string = "base-syscalls"

	// FlagNoBaseSyscalls can be used to indicate that no base syscalls should
	// be added at all.
	FlagNoBaseSyscalls string = "no-base-syscalls"
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
)

var (
	// DefaultOutputFile defines the default output location for the recorder.
	DefaultOutputFile = filepath.Join(os.TempDir(), "profile.yaml")

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
		"close",
		"close_range",
		"dup2",
		"dup3",
		"epoll_ctl",
		"epoll_pwait",
		"execve",
		"exit_group",
		"faccessat2",
		"fchdir",
		"fchown",
		"fcntl",
		"fstat",
		"fstatfs",
		"futex",
		"getcwd",
		"getdents64",
		"getegid",
		"geteuid",
		"getgid",
		"getpid",
		"getppid",
		"getrandom",
		"getuid",
		"ioctl",
		"lseek",
		"mmap",
		"mount",
		"mprotect",
		"nanosleep",
		"newfstatat",
		"openat",
		"openat2",
		"pivot_root",
		"prctl",
		"prlimit64",
		"pselect6",
		"read",
		"readlink",
		"rseq",
		"rt_sigaction",
		"rt_sigprocmask",
		"rt_sigreturn",
		"select",
		"set_robust_list",
		"set_tid_address",
		"setgid",
		"setgroups",
		"sethostname",
		"setresgid",
		"setresuid",
		"setsid",
		"setuid",
		"stat",
		"statfs",
		"statx",
		"tgkill",
		"umask",
		"umount2",
		"uname",
		"write",
	}
)
