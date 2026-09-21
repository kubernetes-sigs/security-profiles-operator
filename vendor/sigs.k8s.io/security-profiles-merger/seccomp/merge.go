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
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = spm.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = spm.ErrNilProfile
	// ErrMoreProblems is returned alongside the failures a report lists
	// when it left others out: every validator bounds how many it reports,
	// since a profile holds as many as it holds rules. A caller matching a
	// sentinel must read a match here as "and possibly others", because a
	// failure the profile holds can be absent from the error reporting it.
	ErrMoreProblems = spm.ErrMoreProblems
	// ErrNotifyWithoutListener is returned by Validate for a profile that
	// applies SCMP_ACT_NOTIFY while naming no listener to hand the
	// notification to, and by Intersect and Union if a result would ever
	// hold one. runc sets SECCOMP_FILTER_FLAG_NEW_LISTENER for any such
	// filter and then refuses to create the container without a
	// listenerPath, so the profile does not load at all.
	ErrNotifyWithoutListener = errors.New("SCMP_ACT_NOTIFY without a listener")
)

// InputError is returned by Intersect and Union when one of the profiles
// they were given fails validation, naming its position among the arguments.
type InputError = spm.InputError

// Intersect merges multiple seccomp profiles via intersection: the resulting
// profile permits a syscall only if all input profiles permit it. For each
// syscall and argument combination, the more restrictive action is chosen.
//
// "Permit" is judged by what runc and crun load through libseccomp and what
// the kernel then runs. Both runtimes skip entries whose action and errno
// equal the profile default, and runc adds an entry with several conditions
// on the same argument index as one rule per condition. libseccomp then
// evaluates the rules of a syscall first-match, in an order of its own that
// ignores the actions: argument index (highest first), then operator class,
// then value. An unconditional rule decides every call of its syscall and
// hides its conditional rules (the first of several unconditional rules
// wins). For conditional rules, the order only does not matter in a few safe
// shapes, where at most one result applies to any call: a single rule;
// single SCMP_CMP_EQ conditions on one argument index with values that
// differ in their lower 32 bits; single conditions sharing one result,
// without a range comparison against a value above 32 bits on an index
// several of them use; and two complementary single conditions, such as
// arg0 == 1 and arg0 != 1. libseccomp compiles other rule sets in ways that
// do not follow the profile, and some it refuses or never finishes
// compiling.
//
// Intersect therefore reads a syscall whose conditional rules do not form a
// safe shape conservatively, as one unconditional rule with the most
// restrictive of its actions and the profile default, which is at least as
// restrictive as whatever libseccomp makes of it. It merges the safe shapes
// precisely where the OCI format can express the result: filters on
// different argument indices are conjoined, identical filters are kept, and
// multiple entries for the same syscall (an OR of filters) are preserved.
// Where the exact intersection is not expressible, for example conflicting
// conditions on the same argument index, the affected calls fall back to the
// more restrictive surrounding action. The result only contains safe shapes
// and never an unconditional entry next to conditional entries for the same
// syscall. Where the merged rules of a syscall would need both, three
// outcomes are possible. A single filtered entry with exactly one condition
// whose operator has a complement (any operator but SCMP_CMP_MASKED_EQ) is
// kept, and the unconditional rule becomes an entry for the complementary
// condition, which is exact. An unconditional rule that differs from the
// profile default only by errno is dropped when filtered entries with a
// different action remain, so the calls it decided get the default's errno
// instead. Anything else collapses to the most restrictive action involved.
// The result therefore never permits more than any input. The same collapse
// bounds the merge cost: past an internal per-syscall budget on the
// pairwise comparison of filtered entries, a syscall collapses to its most
// restrictive action. The budget is the product of the filtered entry
// counts of both sides, so a side without filtered entries for the syscall
// adds no work, and it admits MaxArtifactClausesPerSyscall rules against a
// dozen on the other side.
//
// A second budget bounds how many rules a profile is read as at all. An
// entry loads one rule per name it lists, so the rules of a profile grow as
// the product of its name and condition counts rather than with its size,
// and a profile past the budget is read with every syscall already
// collapsed, which costs one pass over its entries. ValidateArtifact rejects
// an artifact well below that budget (MaxArtifactClauses), so an accepted
// artifact is always merged rule by rule.
//
// These guarantees hold for the program libseccomp compiles for a 64-bit
// architecture. For a 32-bit architecture, libseccomp compares only the
// lower 32 bits of each argument value, which the merge does not model.
//
// ListenerPath and ListenerMetadata are taken from the first profile that
// sets a ListenerPath, since SCMP_ACT_NOTIFY and the listener belong
// together: the action the lattice carries into the result may come from
// either side, and runc refuses to create a container whose filter notifies
// without a listenerPath. Validate requires a listener from every input that
// notifies, so the result always keeps one; an action is never rewritten to
// make that true, and a result that notified without a listener would be
// refused with ErrNotifyWithoutListener rather than emitted.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
// Errno values are compared the way runtimes apply them: an unset errnoRet
// on SCMP_ACT_ERRNO or SCMP_ACT_TRACE means EPERM, and errnoRet on any
// other action is ignored. The result spells EPERM as an unset errnoRet and
// drops ignored values.
//
// Architectures are merged the way runc and crun load them: the filter
// always covers the native architecture, and the listed architectures are
// added to it. An empty list therefore means "native only" and a non-empty
// list means "native plus these", so the intersection is the plain set
// intersection of the lists, which may be empty. Since the native
// architecture is always implied, a list need not name it, and a profile
// that lists only foreign architectures is still valid.
//
// Flags are merged by what they do. SECCOMP_FILTER_FLAG_SPEC_ALLOW loosens
// confinement and survives only if every profile sets it, so a profile
// cannot disable a mitigation the baseline keeps. SECCOMP_FILTER_FLAG_LOG
// hardens auditing and survives if any profile sets it, so a profile cannot
// silence the baseline's logging. SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
// belongs to the listener and comes from the same profile the listener does.
// Unknown flags are rejected by Validate. An empty Flags list means
// "no flags".
//
// Argument conditions are compared as libseccomp evaluates them: valueTwo is
// only significant for SCMP_CMP_MASKED_EQ, where libseccomp masks it with
// value, and is cleared for every other operator, so conditions that differ
// only there are the same filter. A SCMP_CMP_MASKED_EQ with an empty mask
// holds for every value and is dropped, as libseccomp drops it.
//
// A single profile is normalized without merging: it is reduced to the rules
// a runtime loads from it, and syscalls whose conditional rules do not form a
// safe shape collapse as described above. Diff compares profiles in the same
// form but without collapsing, so Diff(p, Intersect(p)) is equal exactly
// when every syscall of p is in a safe shape, and otherwise reports the
// collapsed syscalls.
//
// Syscall entries in the result are grouped: names sharing the same action,
// errno, and argument filters are emitted as one entry, sorted by name, then
// by argument filter, action, and errno, so equal inputs always produce the
// same output.
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return foldProfiles(profiles, intersectRules())
}

// Union merges multiple seccomp profiles via union: the resulting profile
// permits a syscall if any input profile permits it. For each syscall and
// argument combination, the less restrictive action is chosen.
//
// Profiles are read the way Intersect describes, except that a syscall
// whose conditional rules do not form a safe shape is read as one
// unconditional rule with the least restrictive of its actions and the
// profile default. Argument filters of safe shapes are preserved: every
// conditional entry of every input is kept, with its action raised to the
// least restrictive action any input applies to calls matching the filter.
// Where the exact union is not expressible, or would not form a safe shape,
// the result over-approximates in the permissive direction, so it never
// permits less than any input. The per-syscall budget of Intersect applies,
// and a second budget bounds the combined number of filtered entries of
// both sides, since union compares those pairwise as well. The second budget
// applies even when one side has no filtered entries for the syscall; past
// either budget, a syscall collapses to its least restrictive action.
//
// ListenerPath and ListenerMetadata are taken from the first profile that
// sets a ListenerPath, for the reason given for Intersect, and a result that
// notified while naming no listener would be refused with
// ErrNotifyWithoutListener here as well.
// When two profiles share the same default or syscall action, DefaultErrnoRet
// and per-syscall ErrnoRet are taken from the earlier (leftmost) profile.
// Errno values are compared and spelled as described for Intersect.
//
// Flags mirror Intersect: SECCOMP_FILTER_FLAG_SPEC_ALLOW survives if any
// profile sets it, SECCOMP_FILTER_FLAG_LOG only if every profile does, and
// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV follows the listener.
// Architectures are combined. The set the result covers is the union of the
// sets the inputs cover, under the runtime model described for Intersect
// (native plus the listed architectures), but the behaviour on an
// architecture only one input lists is not: there the other input's filter
// applies libseccomp's action for an unlisted architecture, SCMP_ACT_KILL,
// while the result applies the merged rules. That is the permissive
// direction the union promises, so the guarantee holds.
//
// Argument conditions, single profiles, and output ordering are handled as
// described for Intersect.
//
// This implements the merge semantics used by the Security Profiles Operator
// for combining recorded profiles.
func Union(profiles ...*specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
	return foldProfiles(profiles, unionRules())
}

func foldProfiles(
	profiles []*specs.LinuxSeccomp, rules ruleMerger,
) (*specs.LinuxSeccomp, error) {
	for idx, profile := range profiles {
		err := Validate(profile)
		if err != nil {
			return nil, &spm.InputError{Index: idx, Err: err}
		}
	}

	result, err := merge.Fold(
		profiles,
		// A single profile is normalized to the form a merge result takes,
		// which is also the form Diff compares.
		func(only *specs.LinuxSeccomp) *specs.LinuxSeccomp {
			return normalizeProfile(only, rules)
		},
		func(left, right *specs.LinuxSeccomp) (*specs.LinuxSeccomp, error) {
			return mergeTwo(left, right, rules), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	err = resolveListener(result)
	if err != nil {
		return nil, err
	}

	result.Syscalls = regroupSyscalls(result.Syscalls)

	slices.Sort(result.Architectures)
	slices.Sort(result.Flags)

	return result, nil
}

// normalizeProfile returns the profile in the form a merge result takes,
// without merging it against anything: syscall entries are reduced to what
// a runtime loads from them and settled for the merge direction (see
// settledSyscalls), errno values and SCMP_ACT_KILL_THREAD are spelled
// canonically, and the other fields are copied.
func normalizeProfile(profile *specs.LinuxSeccomp, rules ruleMerger) *specs.LinuxSeccomp {
	def := defaultClause(profile)

	return &specs.LinuxSeccomp{
		DefaultAction:    def.action,
		DefaultErrnoRet:  outputErrno(def.action, def.errnoRet),
		Architectures:    merge.DeduplicateSlice(profile.Architectures),
		Flags:            merge.DeduplicateSlice(profile.Flags),
		ListenerPath:     profile.ListenerPath,
		ListenerMetadata: profile.ListenerMetadata,
		Syscalls:         settledSyscalls(&rules, profile.Syscalls, def),
	}
}

func mergeTwo(
	left, right *specs.LinuxSeccomp,
	rules ruleMerger,
) *specs.LinuxSeccomp {
	// The merged default follows the same tie-break as every other clause:
	// the left side wins when the actions are equivalent, so its errno
	// survives.
	mergedDefault := pickClause(*defaultClause(left), *defaultClause(right), rules.pick)

	// The listener comes from the first profile that provides one rather
	// than from the left unconditionally: the action lattice can carry
	// SCMP_ACT_NOTIFY in from the right, and a result that notifies without
	// a listenerPath does not load, however loadable both inputs were.
	listener := left
	if left.ListenerPath == "" && right.ListenerPath != "" {
		listener = right
	}

	merged := &specs.LinuxSeccomp{
		DefaultAction:    mergedDefault.action,
		DefaultErrnoRet:  outputErrno(mergedDefault.action, mergedDefault.errnoRet),
		ListenerPath:     listener.ListenerPath,
		ListenerMetadata: listener.ListenerMetadata,
	}

	merged.Flags = mergeFlags(left.Flags, right.Flags, rules.intersect, listener == left)

	if rules.intersect {
		merged.Architectures = merge.IntersectSlice(left.Architectures, right.Architectures)
	} else {
		merged.Architectures = merge.UnionSlice(left.Architectures, right.Architectures)
	}

	merged.Syscalls = rules.mergeProfileSyscalls(left, right, &mergedDefault)

	return merged
}

// resolveListener keeps SCMP_ACT_NOTIFY and the listener together in the
// result, for either strategy. runc refuses to create a container for a
// filter that notifies without a listenerPath, so such a result is refused
// rather than emitted, and rather than rewritten: the action a caller wrote
// is the supervisor it asked for, and both rewriting it and dropping it
// silently lose that.
//
// It holds for every result the two merges can build. The action of an entry
// is always the action of an input entry (see pickClause), Validate requires
// a listenerPath from every input that notifies, and the listener is taken
// from the first input that sets one, so an input notifies only alongside a
// listener the result keeps. The default action is never SCMP_ACT_NOTIFY
// either, since Validate rejects it on every input and the merged default is
// one of theirs. This is the check that keeps that reasoning true.
func resolveListener(profile *specs.LinuxSeccomp) error {
	if profile.ListenerPath != "" {
		return nil
	}

	notifies := func(entry specs.LinuxSyscall) bool { return entry.Action == specs.ActNotify }
	if !slices.ContainsFunc(profile.Syscalls, notifies) {
		return nil
	}

	return fmt.Errorf("merge: %w", ErrNotifyWithoutListener)
}

// regroupSyscalls drops entries without names, merges entries sharing the
// same action, errno, and argument filters into one multi-name entry, and
// sorts the result by first name, then by argument filter, action, and
// errno, which is a total order over the result.
//
// Every entry it is given carries exactly one name, so the name check only
// guards the sort below, which reads the first name of each group.
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
// same rules as Union, including how errno values are compared and spelled.
// Unlike Union, this function operates on bare syscall slices without a
// profile-level DefaultAction, so no entries are elided.
//
// Without a default, the result is only meaningful relative to the default
// the caller loads it with. UnionSyscalls assumes that this default is the
// same for both lists and the result, and that it is more restrictive than
// every action in the lists, as in an allowlist; a runtime would skip an
// entry equal to it. Under that assumption the result never permits less
// than either list. Where a syscall's rules do not form a safe shape (see
// Intersect), in a list or in the result, the syscall collapses to one
// unconditional entry with the least restrictive action involved, which
// decides calls the lists leave to the default, but never less permissively
// than the default would. A syscall without an unconditional entry in either
// list is never collapsed for the merge budget, since its union takes linear
// work. Entries sharing the same action, errno, and argument filters are
// grouped into one multi-name entry, sorted by name.
//
// This function does not validate its inputs. Callers should ensure that
// actions are known and that every entry has at least one name, or call
// Validate on the enclosing profile first.
func UnionSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	return regroupSyscalls(unionRules().mergeBareSyscalls(left, right))
}

// IntersectSyscalls merges two syscall lists via intersection: for each
// syscall name present in both lists, the more restrictive action is chosen
// per argument region, following the same rules as Intersect, including
// how errno values are compared and spelled. Unlike Intersect, this function
// operates on bare syscall slices without a profile-level DefaultAction.
//
// It makes the same assumption as UnionSyscalls: the caller loads both lists
// and the result with one default that is more restrictive than every action
// in the lists. Under that assumption the result never permits more than
// either list. Calls a list leaves to the default are left to it in the
// result, so syscalls present in only one list are dropped, and a
// conditional entry survives only where the other list constrains every call
// it matches. Where a syscall's rules do not form a safe shape (see
// Intersect), in a list or in the result, or its merge exceeds the budget of
// Intersect, the syscall is dropped, which leaves it to the default. Entries
// sharing the same action, errno, and argument filters are grouped into one
// multi-name entry, sorted by name.
//
// This function does not validate its inputs. Callers should ensure that
// actions are known and that every entry has at least one name, or call
// Validate on the enclosing profile first.
func IntersectSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	return regroupSyscalls(intersectRules().mergeBareSyscalls(left, right))
}
