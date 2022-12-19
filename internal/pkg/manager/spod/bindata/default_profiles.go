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

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// DefaultLogEnricherProfile returns the default seccomp profile for log enricher.
func DefaultLogEnricherProfile() *seccompprofileapi.SeccompProfile {
	namespace := config.GetOperatorNamespace()
	labels := map[string]string{"app": config.OperatorName}
	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.LogEnricherProfile,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccomp.ActLog,
		},
	}
}

// DefaultProfiles returns the default profiles deployed by the operator.
func DefaultProfiles() []*seccompprofileapi.SeccompProfile {
	namespace := config.GetOperatorNamespace()
	labels := map[string]string{"app": config.OperatorName}
	return []*seccompprofileapi.SeccompProfile{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-1.19.1",
				Namespace: namespace,
				Labels:    labels,
			},
			Spec: seccompprofileapi.SeccompProfileSpec{
				DefaultAction: seccomp.ActErrno,
				Architectures: []seccompprofileapi.Arch{
					seccompprofileapi.Arch(seccomp.ArchX86_64),
					seccompprofileapi.Arch(seccomp.ArchX86),
					seccompprofileapi.Arch(seccomp.ArchX32),
				},
				Syscalls: []*seccompprofileapi.Syscall{
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
