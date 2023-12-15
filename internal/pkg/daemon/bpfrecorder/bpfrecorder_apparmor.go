//go:build linux && !no_bpf
// +build linux,!no_bpf

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

package bpfrecorder

import (
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

type syscallTracepoint struct {
	category string
	program  string
	name     string
}

var apparmorSyscallTracepoints = []syscallTracepoint{
	{
		category: "syscalls",
		program:  "syscall__execve",
		name:     "sys_enter_execve",
	},
	{
		category: "syscalls",
		program:  "syscall__execveat",
		name:     "sys_enter_execveat",
	},
	{
		category: "syscalls",
		program:  "syscall__open",
		name:     "sys_enter_open",
	},
	{
		category: "syscalls",
		program:  "syscall__exit_open",
		name:     "sys_exit_open",
	},
	{
		category: "syscalls",
		program:  "syscall__openat",
		name:     "sys_enter_openat",
	},
	{
		category: "syscalls",
		program:  "syscall__exit_openat",
		name:     "sys_exit_openat",
	},
	{
		category: "syscalls",
		program:  "syscall__close",
		name:     "sys_enter_close",
	},
	{
		category: "syscalls",
		program:  "syscall__mmap",
		name:     "sys_enter_mmap",
	},
	{
		category: "syscalls",
		program:  "syscall__write",
		name:     "sys_enter_write",
	},
	{
		category: "syscalls",
		program:  "syscall__read",
		name:     "sys_enter_read",
	},
	{
		category: "syscalls",
		program:  "syscall__socket",
		name:     "sys_enter_socket",
	},
	{
		category: "syscalls",
		program:  "syscall__exit",
		name:     "sys_enter_exit",
	},
	{
		category: "syscalls",
		program:  "syscall__exit_group",
		name:     "sys_enter_exit_group",
	},
}

type AppArmor struct{}

func (*AppArmor) AddSpecificInstrumentation(b *BpfRecorder, module *bpf.Module) error {
	for _, tracepoint := range apparmorSyscallTracepoints {
		b.logger.Info("Getting bpf program " + tracepoint.program)
		programApparmor, err := b.GetProgram(module, tracepoint.program)
		if err != nil {
			return fmt.Errorf("get %s program: %w", tracepoint.program, err)
		}
		b.logger.Info("Attaching bpf tracepoint")
		if _, err := b.AttachTracepoint(programApparmor, tracepoint.category, tracepoint.name); err != nil {
			return fmt.Errorf("attach tracepoint: %w", err)
		}
	}

	b.logger.Info("Getting bpf program " + "trace_cap_capable")
	programApparmor, err := b.GetProgram(module, "trace_cap_capable")
	if err != nil {
		return fmt.Errorf("get %s program: %w", "trace_cap_capable", err)
	}
	b.logger.Info("Attaching bpf kprobes")

	if _, err := programApparmor.AttachKprobe("cap_capable"); err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}

	return nil
}

func (*AppArmor) SetupAndProcessSpecificEvents(b *BpfRecorder, module *bpf.Module) error {
	const timeout = 300

	if b.recordingMode == recordingAppArmor {
		apparmorEvents := make(chan []byte)
		apparmorRingbuffer, err := b.InitRingBuf(module,
			"apparmor_events",
			apparmorEvents)
		if err != nil {
			return fmt.Errorf("init apparmor_events ringbuffer: %w", err)
		}
		b.PollRingBuffer(apparmorRingbuffer, timeout)
		b.lockAppArmorRecording.Lock()
		go b.handleAppArmorEvents(apparmorEvents)
	}

	return nil
}
