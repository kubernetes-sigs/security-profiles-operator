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
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = merge.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = merge.ErrNilProfile
)

// Intersect merges multiple seccomp profiles via intersection: the resulting
// profile permits a syscall only if all input profiles permit it. For each
// syscall, the more restrictive action is chosen. When argument filters differ
// and the intersection cannot be computed precisely, the syscall is denied
// (conservative).
//
// ListenerPath and ListenerMetadata are taken from the first profile.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
//
// An empty Architectures list is treated as "unspecified" and defers to the
// other profile. Per the OCI runtime-spec, empty means "native architecture
// only", but the native architecture is unknown at merge time. Callers that
// need precise architecture intersection should populate the native
// architecture explicitly before merging.
//
// An empty Flags list is likewise treated as "unspecified" and defers to the
// other profile, consistent with the architecture handling.
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return foldProfiles(profiles, mergeStrategy{pick: MoreRestrictive, isIntersect: true})
}

// Union merges multiple seccomp profiles via union: the resulting profile
// permits a syscall if any input profile permits it. For each syscall, the
// less restrictive action is chosen. Argument filters are combined.
//
// ListenerPath and ListenerMetadata are taken from the first profile.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
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

	slices.SortFunc(result.Syscalls, func(a, b specs.LinuxSyscall) int {
		return cmp.Compare(a.Names[0], b.Names[0])
	})

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
		Syscalls:         mergeSyscalls(left, right, strategy, defaultErrnoRet),
		ListenerPath:     left.ListenerPath,
		ListenerMetadata: left.ListenerMetadata,
	}

	if strategy.isIntersect {
		merged.Architectures = intersectWithEmpty(left.Architectures, right.Architectures)
		merged.Flags = intersectWithEmpty(left.Flags, right.Flags)
	} else {
		merged.Architectures = merge.UnionSlice(left.Architectures, right.Architectures)
		merged.Flags = merge.UnionSlice(left.Flags, right.Flags)
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

// UnionSyscalls merges two syscall lists via union: for each syscall name,
// the less restrictive action is chosen. Unlike Union, this function operates
// on bare syscall slices without a profile-level DefaultAction, so no entries
// are elided. Multi-name entries are normalized to one-name-per-entry and the
// result is sorted by name.
//
// This function does not validate its inputs. Callers should ensure that
// actions are known and that every entry has at least one name, or call
// Validate on the enclosing profile first.
func UnionSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	strategy := mergeStrategy{pick: LessRestrictive, isIntersect: false}
	leftMap := normalizeSyscallList(left)
	rightMap := normalizeSyscallList(right)

	result := make([]specs.LinuxSyscall, 0, len(leftMap)+len(rightMap))

	for name, leftEntry := range leftMap {
		if rightEntry, ok := rightMap[name]; ok {
			result = append(result, *pickSyscall(leftEntry, rightEntry, strategy))
		} else {
			result = append(result, cloneSyscall(leftEntry))
		}
	}

	for name, rightEntry := range rightMap {
		if _, inLeft := leftMap[name]; !inLeft {
			result = append(result, cloneSyscall(rightEntry))
		}
	}

	slices.SortFunc(result, func(a, b specs.LinuxSyscall) int {
		return cmp.Compare(a.Names[0], b.Names[0])
	})

	return result
}

// IntersectSyscalls merges two syscall lists via intersection: for each
// syscall name present in both lists, the more restrictive action is chosen.
// Syscalls present in only one list are dropped. Unlike Intersect, this
// function operates on bare syscall slices without a profile-level
// DefaultAction. Multi-name entries are normalized to one-name-per-entry and
// the result is sorted by name.
//
// This function does not validate its inputs. Callers should ensure that
// actions are known and that every entry has at least one name, or call
// Validate on the enclosing profile first.
func IntersectSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	strategy := mergeStrategy{pick: MoreRestrictive, isIntersect: true}
	leftMap := normalizeSyscallList(left)
	rightMap := normalizeSyscallList(right)

	result := make([]specs.LinuxSyscall, 0, min(len(leftMap), len(rightMap)))

	for name, leftEntry := range leftMap {
		if rightEntry, ok := rightMap[name]; ok {
			result = append(result, *pickSyscall(leftEntry, rightEntry, strategy))
		}
	}

	slices.SortFunc(result, func(a, b specs.LinuxSyscall) int {
		return cmp.Compare(a.Names[0], b.Names[0])
	})

	return result
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

// normalizeSyscallList splits multi-name entries into one-name-per-entry and
// merges duplicates. The most permissive action wins to capture the profile's
// full permission envelope, regardless of entry ordering.
func normalizeSyscallList(
	syscalls []specs.LinuxSyscall,
) map[string]*specs.LinuxSyscall {
	withinProfile := mergeStrategy{pick: LessRestrictive, isIntersect: false}

	normalized := make(map[string]*specs.LinuxSyscall)

	for idx := range syscalls {
		entry := &syscalls[idx]

		for _, name := range entry.Names {
			single := &specs.LinuxSyscall{
				Names:    []string{name},
				Action:   entry.Action,
				ErrnoRet: merge.ClonePtr(entry.ErrnoRet),
				Args:     slices.Clone(entry.Args),
			}

			if existing, ok := normalized[name]; ok {
				normalized[name] = pickSyscall(existing, single, withinProfile)
			} else {
				normalized[name] = single
			}
		}
	}

	return normalized
}

func normalizeSyscalls(
	profile *specs.LinuxSeccomp,
) map[string]*specs.LinuxSyscall {
	return normalizeSyscallList(profile.Syscalls)
}

func mergeSyscalls(
	left, right *specs.LinuxSeccomp,
	strategy mergeStrategy,
	mergedDefaultErrnoRet *uint,
) []specs.LinuxSyscall {
	pick := strategy.pick
	leftMap := normalizeSyscalls(left)
	rightMap := normalizeSyscalls(right)

	mergedDefault := pick(left.DefaultAction, right.DefaultAction)

	result := make([]specs.LinuxSyscall, 0, len(leftMap)+len(rightMap))

	for name, leftEntry := range leftMap {
		entry := mergeSyscallEntry(
			leftEntry, rightMap[name],
			left.DefaultAction, right.DefaultAction,
			mergedDefault, mergedDefaultErrnoRet, strategy,
		)
		if entry != nil {
			result = append(result, *entry)
		}
	}

	for name, rightEntry := range rightMap {
		if _, inLeft := leftMap[name]; inLeft {
			continue
		}

		entry := mergeSyscallEntry(
			nil, rightEntry,
			left.DefaultAction, right.DefaultAction,
			mergedDefault, mergedDefaultErrnoRet, strategy,
		)
		if entry != nil {
			result = append(result, *entry)
		}
	}

	return result
}

func mergeSyscallEntry(
	leftEntry, rightEntry *specs.LinuxSyscall,
	leftDefault, rightDefault, mergedDefault specs.LinuxSeccompAction,
	mergedDefaultErrnoRet *uint,
	strategy mergeStrategy,
) *specs.LinuxSyscall {
	pick := strategy.pick

	switch {
	case leftEntry != nil && rightEntry != nil:
		return mergeMatchedSyscall(
			leftEntry, rightEntry, mergedDefault, mergedDefaultErrnoRet, strategy,
		)
	case leftEntry != nil:
		return mergeUnmatchedSyscall(
			leftEntry, rightDefault, mergedDefault, mergedDefaultErrnoRet, pick,
		)
	default:
		return mergeUnmatchedSyscall(
			rightEntry, leftDefault, mergedDefault, mergedDefaultErrnoRet, pick,
		)
	}
}

func mergeMatchedSyscall(
	left, right *specs.LinuxSyscall,
	mergedDefault specs.LinuxSeccompAction,
	mergedDefaultErrnoRet *uint,
	strategy mergeStrategy,
) *specs.LinuxSyscall {
	merged := pickSyscall(left, right, strategy)
	if !actionsEquivalent(merged.Action, mergedDefault) ||
		len(merged.Args) > 0 ||
		!equalUintPtr(merged.ErrnoRet, mergedDefaultErrnoRet) {
		return merged
	}

	return nil
}

func mergeUnmatchedSyscall(
	entry *specs.LinuxSyscall,
	otherDefault, mergedDefault specs.LinuxSeccompAction,
	mergedDefaultErrnoRet *uint,
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction,
) *specs.LinuxSyscall {
	effective := pick(entry.Action, otherDefault)

	// When the picked action came from the other side's default,
	// clear ErrnoRet because the default action's ErrnoRet is
	// already captured in the profile-level DefaultErrnoRet.
	// Safe to use actionsEquivalent here: pick() returns entry.Action
	// when levels tie, and the only same-level pair (ActKill/ActKillThread)
	// ignores ErrnoRet.
	var errnoRet *uint
	if actionsEquivalent(effective, entry.Action) {
		errnoRet = merge.ClonePtr(entry.ErrnoRet)
	}

	if !actionsEquivalent(effective, mergedDefault) ||
		len(entry.Args) > 0 ||
		!equalUintPtr(errnoRet, mergedDefaultErrnoRet) {
		return &specs.LinuxSyscall{
			Names:    slices.Clone(entry.Names),
			Action:   effective,
			ErrnoRet: errnoRet,
			Args:     slices.Clone(entry.Args),
		}
	}

	return nil
}

func pickSyscall(
	left, right *specs.LinuxSyscall,
	strategy mergeStrategy,
) *specs.LinuxSyscall {
	pick := strategy.pick
	pickedAction := pick(left.Action, right.Action)

	result := &specs.LinuxSyscall{
		Names:  left.Names,
		Action: pickedAction,
	}

	if actionsEquivalent(pickedAction, left.Action) {
		result.ErrnoRet = merge.ClonePtr(left.ErrnoRet)
	} else {
		result.ErrnoRet = merge.ClonePtr(right.ErrnoRet)
	}

	args, denied := mergeArgs(left.Args, right.Args, strategy.isIntersect)
	if denied {
		result.Action = specs.ActKillProcess
		result.ErrnoRet = nil
		result.Args = nil
	} else {
		result.Args = args
	}

	return result
}

func mergeArgs(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
	isIntersect bool,
) ([]specs.LinuxSeccompArg, bool) {
	if isIntersect {
		return intersectArgs(leftArgs, rightArgs)
	}

	return unionArgs(leftArgs, rightArgs)
}

func intersectArgs(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	if len(leftArgs) == 0 && len(rightArgs) == 0 {
		return nil, false
	}

	if len(leftArgs) == 0 {
		return slices.Clone(rightArgs), false
	}

	if len(rightArgs) == 0 {
		return slices.Clone(leftArgs), false
	}

	if slices.Equal(leftArgs, rightArgs) {
		return slices.Clone(leftArgs), false
	}

	return mergeArgsByIndex(leftArgs, rightArgs)
}

func mergeArgsByIndex(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	leftByIndex := groupArgsByIndex(leftArgs)
	rightByIndex := groupArgsByIndex(rightArgs)

	result := make([]specs.LinuxSeccompArg, 0, len(leftArgs)+len(rightArgs))

	for idx, leftGroup := range leftByIndex {
		rightGroup, inBoth := rightByIndex[idx]
		if !inBoth {
			result = append(result, leftGroup...)

			continue
		}

		sortArgs(leftGroup)
		sortArgs(rightGroup)

		if !slices.Equal(leftGroup, rightGroup) {
			return nil, true
		}

		result = append(result, leftGroup...)
	}

	for idx, rightGroup := range rightByIndex {
		if _, inLeft := leftByIndex[idx]; !inLeft {
			result = append(result, rightGroup...)
		}
	}

	slices.SortFunc(result, func(a, b specs.LinuxSeccompArg) int {
		return cmp.Compare(a.Index, b.Index)
	})

	return result, false
}

func sortArgs(args []specs.LinuxSeccompArg) {
	slices.SortFunc(args, func(left, right specs.LinuxSeccompArg) int {
		return cmp.Or(
			cmp.Compare(left.Index, right.Index),
			cmp.Compare(left.Value, right.Value),
			cmp.Compare(left.ValueTwo, right.ValueTwo),
			cmp.Compare(left.Op, right.Op),
		)
	})
}

func groupArgsByIndex(
	args []specs.LinuxSeccompArg,
) map[uint][]specs.LinuxSeccompArg {
	grouped := make(map[uint][]specs.LinuxSeccompArg)

	for _, arg := range args {
		grouped[arg.Index] = append(grouped[arg.Index], arg)
	}

	return grouped
}

// unionArgs combines argument filters from two syscall entries. No args means
// "match unconditionally", which is already the most permissive state.
// Unioning with an unconstrained side yields unconstrained.
//
// When both sides have identical args the shared filters are preserved.
// When args differ, the result drops to unconstrained (no args) because
// OCI seccomp AND-joins args within a single entry and cannot express OR.
// Dropping args over-approximates in the permissive direction, which is
// correct for union semantics.
func unionArgs(
	leftArgs, rightArgs []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	if len(leftArgs) == 0 || len(rightArgs) == 0 {
		return nil, false
	}

	leftSorted := slices.Clone(leftArgs)
	rightSorted := slices.Clone(rightArgs)

	sortArgs(leftSorted)
	sortArgs(rightSorted)

	if slices.Equal(leftSorted, rightSorted) {
		return slices.Clone(leftArgs), false
	}

	return nil, false
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
