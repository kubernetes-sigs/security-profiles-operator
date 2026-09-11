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
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = merge.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = merge.ErrNilProfile
)

// Intersect merges multiple seccomp profiles via intersection: the resulting
// profile permits a syscall only if all input profiles permit it. For each
// syscall and argument combination, the more restrictive action is chosen.
//
// Argument filters are honored precisely where the OCI format can express
// the result: filters on different argument indices are conjoined, identical
// filters are kept, and multiple entries for the same syscall (an OR of
// filters) are preserved. Where the exact intersection is not expressible,
// for example conflicting conditions on the same argument index, the
// affected calls fall back to the more restrictive surrounding action. The
// result therefore never permits more than any input.
//
// Within a single profile, entries are evaluated the way runc and libseccomp
// load them: entries equal to the profile default are ignored, an
// unconditional entry applies to every call of its syscall and overrides
// conditional entries for the same syscall (the first unconditional entry
// wins), and otherwise the least restrictive action among matching
// conditional entries applies. Several conditions on the same argument index
// within one entry are alternatives, as runc loads them. The result never
// carries an unconditional entry next to conditional entries for the same
// syscall; where that would be needed, a single filter is rewritten with its
// complement and anything else collapses to the more restrictive action.
//
// ListenerPath and ListenerMetadata are taken from the first profile.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
//
// An empty Architectures list is treated as "unspecified" and defers to the
// other profile. Per the OCI runtime-spec, empty means "native architecture
// only", but the native architecture is unknown at merge time. Callers that
// need precise architecture intersection should populate the native
// architecture explicitly before merging, for example with
// PopulateNativeArchitecture. Two non-empty lists with no architecture in
// common intersect to an empty list, which the runtime-spec again reads as
// "native architecture only".
//
// Flags are merged by what they do. SECCOMP_FILTER_FLAG_SPEC_ALLOW loosens
// confinement and survives only if every profile sets it, so a profile
// cannot disable a mitigation the baseline keeps. SECCOMP_FILTER_FLAG_LOG
// hardens auditing and survives if any profile sets it, so a profile cannot
// silence the baseline's logging. SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
// belongs to the listener and, like ListenerPath, is taken from the first
// profile. Unknown flags are treated like SECCOMP_FILTER_FLAG_LOG. An empty
// Flags list means "no flags".
//
// Argument conditions are compared as runtimes evaluate them: valueTwo is
// only significant for SCMP_CMP_MASKED_EQ and is cleared for every other
// operator, so conditions that differ only there are the same filter.
//
// A single profile is normalized as if merged with itself, so the result is
// deterministic and follows the same evaluation model as a merge.
//
// Syscall entries in the result are grouped: names sharing the same action,
// errno, and argument filters are emitted as one entry, sorted by name, then
// by argument filter, action, and errno, so equal inputs always produce the
// same output.
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return foldProfiles(profiles, mergeStrategy{pick: MoreRestrictive, isIntersect: true})
}

// Union merges multiple seccomp profiles via union: the resulting profile
// permits a syscall if any input profile permits it. For each syscall and
// argument combination, the less restrictive action is chosen.
//
// Argument filters are preserved: every conditional entry of every input is
// kept, with its action raised to the least restrictive action any input
// applies to calls matching the filter. Where the exact union is not
// expressible the result over-approximates in the permissive direction, so
// it never permits less than any input. The evaluation model within a
// profile is the one described for Intersect.
//
// ListenerPath and ListenerMetadata are taken from the first profile.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
//
// Flags mirror Intersect: SECCOMP_FILTER_FLAG_SPEC_ALLOW survives if any
// profile sets it, SECCOMP_FILTER_FLAG_LOG only if every profile does, and
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV comes from the first profile.
// Architectures are combined.
//
// Argument conditions, single profiles, and output ordering are handled as
// described for Intersect.
//
// This implements the merge semantics used by the Security Profiles Operator
// for combining recorded profiles.
func Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return foldProfiles(profiles, mergeStrategy{pick: LessRestrictive, isIntersect: false})
}

type mergeStrategy struct {
	pick        func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction
	isIntersect bool
}

func foldProfiles(
	profiles []*specs.LinuxSeccomp, strategy mergeStrategy,
) (*specs.LinuxSeccomp, error) {
	for _, profile := range profiles {
		err := Validate(profile)
		if err != nil {
			return nil, fmt.Errorf("validate: %w", err)
		}
	}

	// A single profile is merged with itself so that it goes through the
	// same evaluation model as a real merge instead of a plain clone.
	if len(profiles) == 1 {
		profiles = []*specs.LinuxSeccomp{profiles[0], profiles[0]}
	}

	result, err := merge.Fold(
		profiles,
		cloneProfile,
		func(a, b *specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
			return mergeTwo(a, b, strategy), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("fold: %w", err)
	}

	result.Syscalls = regroupSyscalls(result.Syscalls)

	slices.Sort(result.Architectures)
	slices.Sort(result.Flags)

	return result, nil
}

func mergeTwo(
	left, right *specs.LinuxSeccomp,
	strategy mergeStrategy,
) *specs.LinuxSeccomp {
	pick := strategy.pick

	defaultErrnoRet := mergeErrnoRet(
		left.DefaultErrnoRet,
		right.DefaultErrnoRet,
		left.DefaultAction,
		right.DefaultAction,
		pick,
	)

	merged := &specs.LinuxSeccomp{
		DefaultAction:    pick(left.DefaultAction, right.DefaultAction),
		DefaultErrnoRet:  defaultErrnoRet,
		ListenerPath:     left.ListenerPath,
		ListenerMetadata: left.ListenerMetadata,
	}

	mergedDefault := &clause{
		action:   merged.DefaultAction,
		errnoRet: defaultErrnoRet,
		args:     nil,
	}

	merged.Flags = mergeFlags(left.Flags, right.Flags, strategy.isIntersect)

	if strategy.isIntersect {
		merged.Syscalls = intersectRules().mergeProfileSyscalls(left, right, mergedDefault)
		merged.Architectures = intersectWithEmpty(left.Architectures, right.Architectures)
	} else {
		merged.Syscalls = unionRules().mergeProfileSyscalls(left, right, mergedDefault)
		merged.Architectures = merge.UnionSlice(left.Architectures, right.Architectures)
	}

	return merged
}

func intersectWithEmpty[T comparable](left, right []T) []T {
	if len(left) == 0 {
		return slices.Clone(right)
	}

	if len(right) == 0 {
		return slices.Clone(left)
	}

	return merge.IntersectSlice(left, right)
}

// regroupSyscalls drops entries without names, merges entries sharing the
// same action, errno, and argument filters into one multi-name entry, and
// sorts the result by first name, then by argument filter, action, and
// errno, which is a total order over the result.
func regroupSyscalls(syscalls []specs.LinuxSyscall) []specs.LinuxSyscall {
	type group struct {
		entry   specs.LinuxSyscall
		argsKey string
		names   map[string]struct{}
	}

	groups := make(map[string]*group)

	for idx := range syscalls {
		entry := &syscalls[idx]
		if len(entry.Names) == 0 {
			continue
		}

		key := groupKey(entry)

		current, ok := groups[key]
		if !ok {
			args := sortedArgs(entry.Args)
			current = &group{
				entry: specs.LinuxSyscall{
					Names:    nil,
					Action:   entry.Action,
					ErrnoRet: merge.ClonePtr(entry.ErrnoRet),
					Args:     args,
				},
				argsKey: sortedArgsKey(args),
				names:   make(map[string]struct{}),
			}
			groups[key] = current
		}

		for _, name := range entry.Names {
			current.names[name] = struct{}{}
		}
	}

	ordered := make([]*group, 0, len(groups))

	for _, current := range groups {
		current.entry.Names = slices.Sorted(maps.Keys(current.names))
		ordered = append(ordered, current)
	}

	slices.SortFunc(ordered, func(a, b *group) int {
		return cmp.Or(
			cmp.Compare(a.entry.Names[0], b.entry.Names[0]),
			cmp.Compare(a.argsKey, b.argsKey),
			cmp.Compare(a.entry.Action, b.entry.Action),
			compareUintPtr(a.entry.ErrnoRet, b.entry.ErrnoRet),
		)
	})

	result := make([]specs.LinuxSyscall, 0, len(ordered))
	for _, current := range ordered {
		result = append(result, current.entry)
	}

	return result
}

func groupKey(entry *specs.LinuxSyscall) string {
	var builder strings.Builder

	builder.WriteString(string(entry.Action))
	builder.WriteByte('|')

	if entry.ErrnoRet != nil {
		builder.WriteString(strconv.FormatUint(uint64(*entry.ErrnoRet), 10))
	}

	builder.WriteByte('|')
	builder.WriteString(argsKey(entry.Args))

	return builder.String()
}

// UnionSyscalls merges two syscall lists via union: for each syscall name,
// the less restrictive action is chosen per argument region, following the
// same rules as Union. Unlike Union, this function operates on bare syscall
// slices without a profile-level DefaultAction, so no entries are elided.
// Entries sharing the same action, errno, and argument filters are grouped
// into one multi-name entry, sorted by name.
//
// This function does not validate its inputs. Callers should ensure that
// actions are known and that every entry has at least one name, or call
// Validate on the enclosing profile first.
func UnionSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	return regroupSyscalls(unionRules().mergeBareSyscalls(left, right))
}

// IntersectSyscalls merges two syscall lists via intersection: for each
// syscall name present in both lists, the more restrictive action is chosen
// per argument region, following the same rules as Intersect. Syscalls
// present in only one list are dropped. Unlike Intersect, this function
// operates on bare syscall slices without a profile-level DefaultAction, so
// a conditional entry survives only where the other list constrains the same
// syscall. Entries sharing the same action, errno, and argument filters are
// grouped into one multi-name entry, sorted by name.
//
// This function does not validate its inputs. Callers should ensure that
// actions are known and that every entry has at least one name, or call
// Validate on the enclosing profile first.
func IntersectSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	return regroupSyscalls(intersectRules().mergeBareSyscalls(left, right))
}

func cloneSyscall(syscall *specs.LinuxSyscall) specs.LinuxSyscall {
	clone := specs.LinuxSyscall{
		Names:  slices.Clone(syscall.Names),
		Action: syscall.Action,
		Args:   slices.Clone(syscall.Args),
	}

	clone.ErrnoRet = merge.ClonePtr(syscall.ErrnoRet)

	return clone
}

func mergeErrnoRet(
	leftRet, rightRet *uint,
	leftAction, rightAction specs.LinuxSeccompAction,
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction,
) *uint {
	// When both actions are equivalent, leftmost wins unconditionally,
	// even if left's ErrnoRet is nil (meaning "no errno override").
	if actionsEquivalent(leftAction, rightAction) {
		return merge.ClonePtr(leftRet)
	}

	picked := pick(leftAction, rightAction)

	if actionsEquivalent(picked, leftAction) {
		return merge.ClonePtr(leftRet)
	}

	return merge.ClonePtr(rightRet)
}

func cloneProfile(profile *specs.LinuxSeccomp) *specs.LinuxSeccomp {
	clone := &specs.LinuxSeccomp{
		DefaultAction:    profile.DefaultAction,
		DefaultErrnoRet:  merge.ClonePtr(profile.DefaultErrnoRet),
		ListenerPath:     profile.ListenerPath,
		ListenerMetadata: profile.ListenerMetadata,
	}

	clone.Architectures = slices.Clone(profile.Architectures)
	clone.Flags = slices.Clone(profile.Flags)
	clone.Syscalls = make([]specs.LinuxSyscall, len(profile.Syscalls))

	for idx := range profile.Syscalls {
		clone.Syscalls[idx] = cloneSyscall(&profile.Syscalls[idx])
	}

	return clone
}
