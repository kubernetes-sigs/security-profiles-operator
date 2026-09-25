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

package util

import (
	"errors"
	"fmt"
	"math"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

// ErrSeccompArgOutOfRange is returned if a runtime-spec seccomp value does
// not fit into the SeccompProfile API.
var ErrSeccompArgOutOfRange = errors.New("seccomp value out of range")

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

func syscallsFromOCI(syscalls []specs.LinuxSyscall) ([]seccompprofile.Syscall, error) {
	result := make([]seccompprofile.Syscall, 0, len(syscalls))

	for _, sc := range syscalls {
		errnoRet, err := errnoRetFromOCI(sc.ErrnoRet)
		if err != nil {
			return nil, fmt.Errorf("syscalls %v: %w", sc.Names, err)
		}

		args, err := argsFromOCI(sc.Args)
		if err != nil {
			return nil, fmt.Errorf("syscalls %v: %w", sc.Names, err)
		}

		result = append(result, seccompprofile.Syscall{
			Names:    sc.Names,
			Action:   seccompprofile.Action(sc.Action),
			ErrnoRet: errnoRet,
			Args:     args,
		})
	}

	return result, nil
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

// argsFromOCI converts the runtime-spec syscall arguments into the CRD
// representation. Arguments which the CRD cannot hold are an error instead of
// being dropped, because dropping an argument would widen the rule.
func argsFromOCI(args []specs.LinuxSeccompArg) ([]seccompprofile.Arg, error) {
	if len(args) == 0 {
		return nil, nil
	}

	result := make([]seccompprofile.Arg, 0, len(args))

	for _, arg := range args {
		if arg.Index > math.MaxInt32 {
			return nil, fmt.Errorf("%w: index %d", ErrSeccompArgOutOfRange, arg.Index)
		}

		if arg.Value > math.MaxInt64 {
			return nil, fmt.Errorf("%w: value %d", ErrSeccompArgOutOfRange, arg.Value)
		}

		if arg.ValueTwo > math.MaxInt64 {
			return nil, fmt.Errorf("%w: valueTwo %d", ErrSeccompArgOutOfRange, arg.ValueTwo)
		}

		idx := int32(arg.Index)
		result = append(result, seccompprofile.Arg{
			Index:    &idx,
			Value:    int64(arg.Value),
			ValueTwo: int64(arg.ValueTwo),
			Op:       seccompprofile.Operator(arg.Op),
		})
	}

	return result, nil
}

func errnoRetToOCI(errnoRet int32) *uint {
	if errnoRet <= 0 {
		return nil
	}

	val := uint(errnoRet)

	return &val
}

func errnoRetFromOCI(errnoRet *uint) (int32, error) {
	if errnoRet == nil {
		return 0, nil
	}

	if *errnoRet > math.MaxInt32 {
		return 0, fmt.Errorf("%w: errnoRet %d", ErrSeccompArgOutOfRange, *errnoRet)
	}

	return int32(*errnoRet), nil
}
