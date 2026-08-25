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
	"errors"
	"fmt"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const maxSyscallArgIndex = 5

var (
	// ErrUnknownAction is returned when a profile contains an unrecognized
	// seccomp action.
	ErrUnknownAction = errors.New("unknown seccomp action")
	// ErrEmptySyscallNames is returned when a syscall entry has no names.
	ErrEmptySyscallNames = errors.New("syscall entry has no names")
	// ErrEmptySyscallName is returned when a syscall entry contains an
	// empty string in its name list.
	ErrEmptySyscallName = errors.New("empty syscall name")
	// ErrDuplicateSyscallName is returned when the same syscall name
	// appears in more than one syscall entry.
	ErrDuplicateSyscallName = errors.New("duplicate syscall name")
	// ErrUnknownOperator is returned when a syscall arg contains an
	// unrecognized comparison operator.
	ErrUnknownOperator = errors.New("unknown seccomp operator")
	// ErrArgIndexOutOfRange is returned when a syscall arg index exceeds
	// the maximum (5).
	ErrArgIndexOutOfRange = errors.New("syscall arg index out of range")
	// ErrUnknownArch is returned when a profile contains an unrecognized
	// architecture.
	ErrUnknownArch = errors.New("unknown architecture")
	// ErrDuplicateArch is returned when the same architecture appears
	// more than once.
	ErrDuplicateArch = errors.New("duplicate architecture")
	// ErrUnknownFlag is returned when a profile contains an unrecognized
	// seccomp flag.
	ErrUnknownFlag = errors.New("unknown seccomp flag")
	// ErrDuplicateFlag is returned when the same flag appears more than
	// once.
	ErrDuplicateFlag = errors.New("duplicate seccomp flag")
)

// Validate checks that a seccomp profile contains only known actions.
// Unknown actions are silently treated as maximally restrictive during
// merge, which may produce unexpected results. Calling Validate before
// merge surfaces these problems early. All validation failures are
// collected and returned together.
func Validate(profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateAction(profile.DefaultAction, "default action")
	if err != nil {
		errs = append(errs, err)
	}

	for idx := range profile.Syscalls {
		if len(profile.Syscalls[idx].Names) == 0 {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d: %w", idx, ErrEmptySyscallNames,
			))
		}

		if slices.Contains(profile.Syscalls[idx].Names, "") {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d: %w", idx, ErrEmptySyscallName,
			))
		}

		err := validateAction(
			profile.Syscalls[idx].Action,
			fmt.Sprintf("syscall entry %d action", idx),
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally detects
// duplicate syscall names across entries, unknown architectures, unknown
// flags, unknown arg operators, and out-of-range arg indices. The OCI
// runtime-spec allows the same syscall to appear in multiple entries (for
// example with different argument filters), so the merge path uses Validate
// which permits this. ValidateStrict is intended for user-authored profiles
// where duplicates are likely mistakes.
func ValidateStrict(profile *specs.LinuxSeccomp) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

	err = validateDuplicateSyscallNames(profile.Syscalls)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateArchitectures(profile.Architectures)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateArchitectures(profile.Architectures)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateFlags(profile.Flags)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateDuplicateFlags(profile.Flags)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateSyscallArgs(profile.Syscalls)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func validateDuplicateSyscallNames(syscalls []specs.LinuxSyscall) error {
	seen := make(map[string]int)

	var errs []error

	for idx, sc := range syscalls {
		for _, name := range sc.Names {
			if prev, ok := seen[name]; ok {
				errs = append(errs, fmt.Errorf(
					"syscall %q in entries %d and %d: %w",
					name, prev, idx, ErrDuplicateSyscallName,
				))
			} else {
				seen[name] = idx
			}
		}
	}

	return errors.Join(errs...)
}

func validateAction(action specs.LinuxSeccompAction, context string) error {
	if restrictiveness(action) == levelUnknown {
		return fmt.Errorf("%s: %w %q", context, ErrUnknownAction, action)
	}

	return nil
}

func isKnownOperator(op specs.LinuxSeccompOperator) bool {
	switch op {
	case specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
		specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		specs.OpMaskedEqual:
		return true
	default:
		return false
	}
}

func isKnownArch(arch specs.Arch) bool {
	switch arch {
	case specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
		specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64,
		specs.ArchRISCV64, specs.ArchLOONGARCH64,
		specs.ArchM68K, specs.ArchSH, specs.ArchSHEB:
		return true
	default:
		return false
	}
}

func isKnownFlag(flag specs.LinuxSeccompFlag) bool {
	switch flag {
	case specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv:
		return true
	default:
		return false
	}
}

func validateArchitectures(archs []specs.Arch) error {
	var errs []error

	for _, arch := range archs {
		if !isKnownArch(arch) {
			errs = append(errs, fmt.Errorf(
				"architecture: %w %q", ErrUnknownArch, arch,
			))
		}
	}

	return errors.Join(errs...)
}

func validateFlags(flags []specs.LinuxSeccompFlag) error {
	var errs []error

	for _, flag := range flags {
		if !isKnownFlag(flag) {
			errs = append(errs, fmt.Errorf(
				"flag: %w %q", ErrUnknownFlag, flag,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateArchitectures(archs []specs.Arch) error {
	seen := make(map[specs.Arch]struct{}, len(archs))

	var errs []error

	for _, arch := range archs {
		if _, ok := seen[arch]; ok {
			errs = append(errs, fmt.Errorf(
				"architecture: %w %q", ErrDuplicateArch, arch,
			))
		} else {
			seen[arch] = struct{}{}
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateFlags(flags []specs.LinuxSeccompFlag) error {
	seen := make(map[specs.LinuxSeccompFlag]struct{}, len(flags))

	var errs []error

	for _, flag := range flags {
		if _, ok := seen[flag]; ok {
			errs = append(errs, fmt.Errorf(
				"flag: %w %q", ErrDuplicateFlag, flag,
			))
		} else {
			seen[flag] = struct{}{}
		}
	}

	return errors.Join(errs...)
}

func validateSyscallArgs(syscalls []specs.LinuxSyscall) error {
	var errs []error

	for idx, sc := range syscalls {
		for argIdx, arg := range sc.Args {
			if !isKnownOperator(arg.Op) {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w %q",
					idx, argIdx, ErrUnknownOperator, arg.Op,
				))
			}

			if arg.Index > maxSyscallArgIndex {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w %d",
					idx, argIdx, ErrArgIndexOutOfRange, arg.Index,
				))
			}
		}
	}

	return errors.Join(errs...)
}
