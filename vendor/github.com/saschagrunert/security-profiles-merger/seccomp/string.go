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

package seccomp

import (
	"fmt"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// FormatProfile returns a human-readable representation of a seccomp profile.
func FormatProfile(profile *specs.LinuxSeccomp) string {
	if profile == nil {
		return "Profile{<nil>}"
	}

	var parts []string

	parts = append(parts, "default:"+string(profile.DefaultAction))

	if profile.DefaultErrnoRet != nil {
		parts = append(parts, fmt.Sprintf("defaultErrno:%d", *profile.DefaultErrnoRet))
	}

	if len(profile.Architectures) > 0 {
		archs := make([]string, len(profile.Architectures))
		for idx, arch := range profile.Architectures {
			archs[idx] = string(arch)
		}

		parts = append(parts, "arch:"+strings.Join(archs, ","))
	}

	if len(profile.Flags) > 0 {
		flags := make([]string, len(profile.Flags))
		for idx, flag := range profile.Flags {
			flags[idx] = string(flag)
		}

		parts = append(parts, "flags:"+strings.Join(flags, ","))
	}

	if profile.ListenerPath != "" {
		parts = append(parts, "listener:"+profile.ListenerPath)

		if profile.ListenerMetadata != "" {
			parts = append(parts, "listenerMeta:"+profile.ListenerMetadata)
		}
	}

	for _, sc := range profile.Syscalls {
		parts = append(parts, formatSyscall(sc))
	}

	return fmt.Sprintf("Profile{%s}", strings.Join(parts, " "))
}

func formatSyscall(syscall specs.LinuxSyscall) string {
	names := strings.Join(syscall.Names, ",")
	action := string(syscall.Action)

	if syscall.ErrnoRet != nil {
		action = fmt.Sprintf("%s(errno:%d)", action, *syscall.ErrnoRet)
	}

	if len(syscall.Args) == 0 {
		return names + "->" + action
	}

	args := make([]string, len(syscall.Args))
	for idx, arg := range syscall.Args {
		if arg.Op == specs.OpMaskedEqual {
			args[idx] = fmt.Sprintf("[%d]%s:%d:%d", arg.Index, arg.Op, arg.Value, arg.ValueTwo)
		} else {
			args[idx] = fmt.Sprintf("[%d]%s:%d", arg.Index, arg.Op, arg.Value)
		}
	}

	return fmt.Sprintf("%s(%s)->%s", names, strings.Join(args, ","), action)
}
