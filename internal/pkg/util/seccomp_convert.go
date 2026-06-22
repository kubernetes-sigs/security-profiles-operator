/*
Copyright 2026 The Kubernetes Authors.

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
	specs "github.com/opencontainers/runtime-spec/specs-go"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func syscallsToOCI(syscalls []seccompprofile.Syscall) []specs.LinuxSyscall {
	result := make([]specs.LinuxSyscall, len(syscalls))

	for i, sc := range syscalls {
		result[i] = specs.LinuxSyscall{
			Names:    sc.Names,
			Action:   specs.LinuxSeccompAction(sc.Action),
			ErrnoRet: errnoRetToOCI(sc.ErrnoRet),
			Args:     argsToOCI(sc.Args),
		}
	}

	return result
}

func syscallsFromOCI(syscalls []specs.LinuxSyscall) []seccompprofile.Syscall {
	result := make([]seccompprofile.Syscall, len(syscalls))

	for i, sc := range syscalls {
		result[i] = seccompprofile.Syscall{
			Names:    sc.Names,
			Action:   seccompprofile.Action(sc.Action),
			ErrnoRet: errnoRetFromOCI(sc.ErrnoRet),
			Args:     argsFromOCI(sc.Args),
		}
	}

	return result
}

func argsToOCI(args []seccompprofile.Arg) []specs.LinuxSeccompArg {
	if len(args) == 0 {
		return nil
	}

	result := make([]specs.LinuxSeccompArg, len(args))

	for i, arg := range args {
		var index uint
		if arg.Index != nil {
			index = uint(*arg.Index)
		}

		result[i] = specs.LinuxSeccompArg{
			Index:    index,
			Value:    uint64(arg.Value),
			ValueTwo: uint64(arg.ValueTwo),
			Op:       specs.LinuxSeccompOperator(arg.Op),
		}
	}

	return result
}

func argsFromOCI(args []specs.LinuxSeccompArg) []seccompprofile.Arg {
	if len(args) == 0 {
		return nil
	}

	result := make([]seccompprofile.Arg, len(args))

	for i, arg := range args {
		idx := int32(arg.Index)
		result[i] = seccompprofile.Arg{
			Index:    &idx,
			Value:    int64(arg.Value),
			ValueTwo: int64(arg.ValueTwo),
			Op:       seccompprofile.Operator(arg.Op),
		}
	}

	return result
}

func errnoRetToOCI(errnoRet int32) *uint {
	if errnoRet == 0 {
		return nil
	}

	val := uint(errnoRet)

	return &val
}

func errnoRetFromOCI(errnoRet *uint) int32 {
	if errnoRet == nil {
		return 0
	}

	return int32(*errnoRet)
}
