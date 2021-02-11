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

package bindata

import (
	"github.com/containers/common/pkg/seccomp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	archX8664 = v1alpha1.Arch(seccomp.ArchX86_64)
	archX86   = v1alpha1.Arch(seccomp.ArchX86)
	archX32   = v1alpha1.Arch(seccomp.ArchX32)
)

// DefaultProfiles returns the default profiles deployed by the operator.
func DefaultProfiles() []*v1alpha1.SeccompProfile {
	return []*v1alpha1.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-1.19.1",
				Namespace: config.GetOperatorNamespace(),
				Labels: map[string]string{
					"app": config.OperatorName,
				},
			},
			Spec: v1alpha1.SeccompProfileSpec{
				TargetWorkload: "default-profiles",
				DefaultAction:  seccomp.ActErrno,
				Architectures:  []*v1alpha1.Arch{&archX8664, &archX86, &archX32},
				Syscalls: []*v1alpha1.Syscall{
					{
						Action: seccomp.ActAllow,
						Names: []string{
							"accept4",
							"access",
							"arch_prctl",
							"bind",
							"brk",
							"capget",
							"capset",
							"chdir",
							"chown",
							"clone",
							"close",
							"connect",
							"dup2",
							"epoll_create",
							"epoll_ctl",
							"epoll_pwait",
							"epoll_wait",
							"eventfd2",
							"execve",
							"exit",
							"exit_group",
							"faccessat",
							"fadvise64",
							"fchdir",
							"fchown",
							"fcntl",
							"fgetxattr",
							"fsetxattr",
							"fstat",
							"fstatfs",
							"futex",
							"getcwd",
							"getdents",
							"getdents64",
							"getegid",
							"geteuid",
							"getgid",
							"getpid",
							"getppid",
							"getrlimit",
							"getuid",
							"io_setup",
							"ioctl",
							"listen",
							"lseek",
							"mkdir",
							"mmap",
							"mprotect",
							"munmap",
							"nanosleep",
							"newfstatat",
							"open",
							"openat",
							"pipe",
							"prctl",
							"pread64",
							"prlimit64",
							"pwrite64",
							"read",
							"recvfrom",
							"recvmsg",
							"rename",
							"rt_sigaction",
							"rt_sigprocmask",
							"rt_sigreturn",
							"rt_sigsuspend",
							"sched_getaffinity",
							"seccomp",
							"select",
							"sendfile",
							"sendmsg",
							"set_robust_list",
							"set_tid_address",
							"setgid",
							"setgroups",
							"setitimer",
							"setresgid",
							"setresuid",
							"setsockopt",
							"setuid",
							"sigaltstack",
							"socket",
							"socketpair",
							"stat",
							"statfs",
							"sysinfo",
							"umask",
							"uname",
							"unlink",
							"utimensat",
							"wait4",
							"write",
							"writev",
						},
					},
				},
			},
		},
	}
}
