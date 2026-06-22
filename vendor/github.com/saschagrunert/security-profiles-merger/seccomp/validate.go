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

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var (
	// ErrUnknownAction is returned when a profile contains an unrecognized
	// seccomp action.
	ErrUnknownAction = errors.New("unknown seccomp action")
	// ErrEmptySyscallNames is returned when a syscall entry has no names.
	ErrEmptySyscallNames = errors.New("syscall entry has no names")
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

func validateAction(action specs.LinuxSeccompAction, context string) error {
	if restrictiveness(action) == levelUnknown {
		return fmt.Errorf("%s: %w %q", context, ErrUnknownAction, action)
	}

	return nil
}
