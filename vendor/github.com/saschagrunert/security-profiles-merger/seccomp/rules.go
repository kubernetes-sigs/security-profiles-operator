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
	"maps"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

// clause is a single rule for one syscall: an action, an optional errno, and
// optional argument filters. A clause without args is unconditional.
//
// The evaluation model for one syscall within a profile mirrors how runc and
// libseccomp load a profile:
//   - entries whose action and errno equal the profile default are skipped;
//   - an unconditional entry applies to every call of the syscall and takes
//     precedence over conditional entries, which libseccomp drops; when
//     several unconditional entries exist, the first one wins;
//   - otherwise, if any conditional clause matches the call, the least
//     restrictive action among the matching conditional clauses applies;
//   - otherwise the profile default applies.
//
// An entry with several conditions on the same argument index is loaded by
// runc as one rule per condition, so it is modeled as one clause per
// condition (an OR) rather than a single conjoined filter.
type clause struct {
	action   specs.LinuxSeccompAction
	errnoRet *uint
	args     []specs.LinuxSeccompArg
}

func (c clause) unconditional() bool { return len(c.args) == 0 }

// sameResult reports whether two clauses yield the same runtime effect,
// ignoring their argument filters. ErrnoRet only matters for actions that
// return it to the caller.
func (c clause) sameResult(other clause) bool {
	if !actionsEquivalent(c.action, other.action) {
		return false
	}

	return !errnoSignificant(c.action) || equalUintPtr(c.errnoRet, other.errnoRet)
}

// pickClause selects between two clauses using the given action preference.
// On a tie the left clause wins, so ErrnoRet comes from the leftmost profile.
func pickClause(
	left, right clause,
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction,
) clause {
	if actionsEquivalent(left.action, right.action) {
		return left
	}

	if actionsEquivalent(pick(left.action, right.action), left.action) {
		return left
	}

	return right
}

func lessRestrictiveClause(left, right clause) clause {
	return pickClause(left, right, LessRestrictive)
}

// syscallRules holds every clause of one profile for a single syscall name.
type syscallRules struct {
	unconditional *clause
	conditional   []clause
}

// collectRules splits syscall entries into per-name clause sets. Multi-name
// entries contribute one clause per name. Entries equal to the profile
// default are skipped when def is non-nil, the first unconditional entry wins
// over later ones, and conditional entries are dropped for names that carry
// an unconditional entry.
func collectRules(syscalls []specs.LinuxSyscall, def *clause) map[string]*syscallRules {
	rules := make(map[string]*syscallRules)

	for idx := range syscalls {
		entry := &syscalls[idx]

		for _, next := range entryClauses(entry) {
			if def != nil && next.sameResult(*def) {
				continue
			}

			for _, name := range entry.Names {
				current, ok := rules[name]
				if !ok {
					current = &syscallRules{unconditional: nil, conditional: nil}
					rules[name] = current
				}

				current.add(next)
			}
		}
	}

	for _, current := range rules {
		if current.unconditional != nil {
			current.conditional = nil
		}
	}

	return rules
}

// entryClauses expands one syscall entry into clauses. An entry whose args
// repeat an argument index yields one single-condition clause per arg, as
// runc loads such entries; every other entry yields exactly one clause.
func entryClauses(entry *specs.LinuxSyscall) []clause {
	base := clause{
		action:   entry.Action,
		errnoRet: merge.ClonePtr(entry.ErrnoRet),
		args:     nil,
	}

	if !hasRepeatedIndex(entry.Args) {
		base.args = sortedArgs(entry.Args)

		return []clause{base}
	}

	clauses := make([]clause, 0, len(entry.Args))

	for _, arg := range entry.Args {
		next := base
		next.errnoRet = merge.ClonePtr(entry.ErrnoRet)
		next.args = []specs.LinuxSeccompArg{arg}
		clauses = append(clauses, next)
	}

	return clauses
}

func hasRepeatedIndex(args []specs.LinuxSeccompArg) bool {
	var seen [maxSyscallArgIndex + 1]bool

	for _, arg := range args {
		if arg.Index > maxSyscallArgIndex {
			continue
		}

		if seen[arg.Index] {
			return true
		}

		seen[arg.Index] = true
	}

	return false
}

// add records a clause. The first unconditional clause wins; conditional
// clauses accumulate.
func (r *syscallRules) add(next clause) {
	next.errnoRet = merge.ClonePtr(next.errnoRet)

	if !next.unconditional() {
		r.conditional = append(r.conditional, next)

		return
	}

	if r.unconditional == nil {
		r.unconditional = &next
	}
}

// fallback returns the clause applied when no conditional clause matches:
// the unconditional clause if present, otherwise the given profile default.
// A nil default (bare syscall lists) yields nil when no unconditional clause
// exists.
func (r *syscallRules) fallback(def *clause) *clause {
	if r != nil && r.unconditional != nil {
		return r.unconditional
	}

	return def
}

func (r *syscallRules) conditionals() []clause {
	if r == nil {
		return nil
	}

	return r.conditional
}

// ruleMerger describes one merge direction over the clause model.
type ruleMerger struct {
	// pick chooses the action for a call that both sides constrain.
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction
	// intersect selects intersection semantics: a fallback exists only when
	// both sides have one, unconstrained regions are dropped, and a clause is
	// emitted for the overlap of two conditional clauses to express "both
	// filters hold". Union keeps every input clause instead.
	intersect bool
}

func intersectRules() ruleMerger {
	return ruleMerger{pick: MoreRestrictive, intersect: true}
}

func unionRules() ruleMerger {
	return ruleMerger{pick: LessRestrictive, intersect: false}
}

func (m ruleMerger) pickClause(left, right clause) clause {
	return pickClause(left, right, m.pick)
}

// mergeRules merges the clauses of one syscall from two sides.
//
// For intersection the result never permits more than either input, and for
// union it never permits less, under the evaluation model documented on the
// clause type. Where the exact result is not expressible, intersection
// falls back to the more restrictive and union to the less restrictive
// surrounding action.
//
// leftDef and rightDef are the profile defaults, or nil for bare syscall
// lists. The returned fallback is the unconditional clause of the result, or
// nil when only the caller's default applies. The conditional clauses are
// not yet collapsed: callers run finishRules with the effective fallback,
// which is the merged default where the fallback is elided.
func (m ruleMerger) mergeRules(
	left, right *syscallRules,
	leftDef, rightDef *clause,
) (*clause, []clause) {
	leftFallback := left.fallback(leftDef)
	rightFallback := right.fallback(rightDef)
	fallback := m.mergeFallback(leftFallback, rightFallback)

	leftConds := left.conditionals()
	rightConds := right.conditionals()

	var conditional []clause

	conditional = append(conditional, m.adjustClauses(leftConds, rightConds, rightFallback)...)
	conditional = append(conditional, m.adjustClauses(rightConds, leftConds, leftFallback)...)

	if m.intersect {
		for _, leftClause := range leftConds {
			for _, rightClause := range rightConds {
				args, ok := conjoinClauseArgs(leftClause.args, rightClause.args)
				if !ok {
					continue
				}

				picked := m.pickClause(leftClause, rightClause)
				picked.args = args
				conditional = append(conditional, picked)
			}
		}
	}

	return fallback, conditional
}

// resolveMixed makes a merged rule set expressible: an unconditional entry
// would override every conditional entry of the same syscall at load time,
// so a non-nil fallback must not be emitted next to conditional clauses.
// A single one-condition clause is rewritten as the clause plus its
// complement carrying the fallback, which is exact. Otherwise the whole
// syscall collapses to one unconditional clause combining the fallback and
// every conditional action with the merge direction's preference, which is
// conservative in the safe direction.
func (m ruleMerger) resolveMixed(fallback *clause, conditional []clause) (*clause, []clause) {
	if fallback == nil || len(conditional) == 0 {
		return fallback, conditional
	}

	conditional = m.foldIntoFallback(fallback, conditional)
	if len(conditional) == 0 {
		return fallback, nil
	}

	if len(conditional) == 1 && len(conditional[0].args) == 1 {
		if complement, ok := complementArg(conditional[0].args[0]); ok {
			rest := clause{
				action:   fallback.action,
				errnoRet: merge.ClonePtr(fallback.errnoRet),
				args:     []specs.LinuxSeccompArg{complement},
			}

			return nil, sortClauses([]clause{conditional[0], rest})
		}
	}

	collapsed := *fallback

	for _, current := range conditional {
		collapsed = m.pickClause(collapsed, current)
	}

	collapsed.args = nil

	return &collapsed, nil
}

// foldIntoFallback drops conditional clauses that differ from the fallback
// only by errno. The rewrite in resolveMixed cannot keep their errno, and
// folding them first lets a single remaining filter use the exact complement
// form instead of collapsing the whole syscall. For union, a stricter clause
// overlapping a folded clause is raised to the fallback first, because the
// folded clause no longer shields the overlap.
func (m ruleMerger) foldIntoFallback(fallback *clause, conditional []clause) []clause {
	byArgs := make(map[string]clause, len(conditional))
	order := make([]string, 0, len(conditional))

	for _, current := range conditional {
		key := argsKey(current.args)

		if existing, ok := byArgs[key]; ok {
			byArgs[key] = lessRestrictiveClause(existing, current)

			continue
		}

		byArgs[key] = current
		order = append(order, key)
	}

	if !m.intersect {
		raiseOverlapsOfRedundant(byArgs, func(current clause) bool {
			return actionsEquivalent(current.action, fallback.action)
		})
	}

	kept := make([]clause, 0, len(conditional))

	for _, key := range order {
		current := byArgs[key]
		if actionsEquivalent(current.action, fallback.action) {
			continue
		}

		kept = append(kept, current)
	}

	return kept
}

// complementArg returns the condition matching exactly the values the given
// condition does not match. Masked comparisons have no complement.
func complementArg(arg specs.LinuxSeccompArg) (specs.LinuxSeccompArg, bool) {
	complement, ok := complementOps[arg.Op]
	if !ok {
		return specs.LinuxSeccompArg{}, false
	}

	return specs.LinuxSeccompArg{
		Index:    arg.Index,
		Value:    arg.Value,
		ValueTwo: 0,
		Op:       complement,
	}, true
}

// complementOps maps each comparison operator to the one matching exactly
// the remaining values. Masked comparisons have no complement.
//
//nolint:gochecknoglobals // immutable lookup table
var complementOps = map[specs.LinuxSeccompOperator]specs.LinuxSeccompOperator{
	specs.OpEqualTo:      specs.OpNotEqual,
	specs.OpNotEqual:     specs.OpEqualTo,
	specs.OpLessThan:     specs.OpGreaterEqual,
	specs.OpGreaterEqual: specs.OpLessThan,
	specs.OpLessEqual:    specs.OpGreaterThan,
	specs.OpGreaterThan:  specs.OpLessEqual,
}

func sortClauses(clauses []clause) []clause {
	slices.SortFunc(clauses, func(a, b clause) int {
		return cmp.Compare(argsKey(a.args), argsKey(b.args))
	})

	return clauses
}

// mergeFallback combines the fallback clauses of both sides. Intersection
// needs both to be present; union takes whichever exists.
func (m ruleMerger) mergeFallback(left, right *clause) *clause {
	switch {
	case left != nil && right != nil:
		picked := m.pickClause(*left, *right)

		return &picked
	case m.intersect:
		return nil
	case left != nil:
		return left
	default:
		return right
	}
}

// adjustClauses returns one clause per entry of clauses, with the action
// combined against what the other side may apply inside the clause's
// argument region. For intersection this lowers the action to what both
// sides allow; for union it raises it to what either side allows.
//
// The other side's fallback applies inside the region unless an other-side
// clause matches everything the clause matches (its filter is a subset), in
// which case the fallback can never be reached there. Intersection also
// lowers the action by every overlapping other-side clause, because the
// result is evaluated as the least restrictive matching clause. Union does
// not need that: every other-side clause is emitted on its own and raises
// the result wherever it matches.
//
// When the other side has no fallback (bare lists) and no overlapping
// clause, the region is unconstrained on that side: intersection drops the
// clause and union keeps it unchanged.
func (m ruleMerger) adjustClauses(
	clauses, others []clause, otherFallback *clause,
) []clause {
	result := make([]clause, 0, len(clauses))

	for _, current := range clauses {
		adjusted, overlapping, subsumed := m.adjustAgainstOthers(current, others)

		if otherFallback != nil && !subsumed {
			adjusted = m.pickClause(adjusted, *otherFallback)
		}

		if m.intersect && otherFallback == nil && !overlapping {
			continue
		}

		adjusted.args = current.args
		result = append(result, adjusted)
	}

	return result
}

// adjustAgainstOthers combines current with every overlapping other-side
// clause (intersection only) and reports whether any other-side clause
// overlaps current and whether one subsumes it.
func (m ruleMerger) adjustAgainstOthers(
	current clause, others []clause,
) (clause, bool, bool) {
	adjusted := current
	overlapping := false
	subsumed := false

	for _, other := range others {
		if argsDisjoint(current.args, other.args) {
			continue
		}

		overlapping = true

		if argsSubset(other.args, current.args) {
			subsumed = true
		}

		if m.intersect {
			adjusted = m.pickClause(adjusted, other)
		}
	}

	return adjusted, overlapping, subsumed
}

// conjoinClauseArgs returns the filter matching the overlap of two
// conditional clauses. Identical filters are kept as-is; otherwise the
// filters must not be provably disjoint and must be conjoinable.
func conjoinClauseArgs(
	left, right []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	if argsKey(left) == argsKey(right) {
		return slices.Clone(left), true
	}

	if argsDisjoint(left, right) {
		return nil, false
	}

	return conjoinArgs(left, right)
}

// collapseClauses merges clauses with identical argument filters (keeping the
// least restrictive, since they always match together) and drops clauses
// that yield the same result as the fallback. Runtimes skip such entries at
// load time, so they cannot shield a call from a stricter overlapping clause;
// for union the stricter clause is raised to the fallback instead.
func (m ruleMerger) collapseClauses(clauses []clause, fallback *clause) []clause {
	byArgs := make(map[string]clause, len(clauses))
	order := make([]string, 0, len(clauses))

	for _, current := range clauses {
		key := argsKey(current.args)

		existing, ok := byArgs[key]
		if !ok {
			byArgs[key] = current
			order = append(order, key)

			continue
		}

		byArgs[key] = lessRestrictiveClause(existing, current)
	}

	if fallback != nil && !m.intersect {
		raiseOverlapsOfRedundant(byArgs, func(current clause) bool {
			return current.sameResult(*fallback)
		})
	}

	result := make([]clause, 0, len(order))

	for _, key := range order {
		current := byArgs[key]
		if fallback != nil && current.sameResult(*fallback) {
			continue
		}

		result = append(result, current)
	}

	return sortClauses(result)
}

// raiseOverlapsOfRedundant raises every clause that is stricter than a
// redundant clause and may match a call the redundant clause also matches.
// Redundant clauses are dropped from the result, or skipped by runtimes when
// they equal the default, so without this the stricter clause would win
// where both match and the union could deny a call an input permits. Raising
// propagates until no such pair remains.
func raiseOverlapsOfRedundant(byArgs map[string]clause, redundant func(clause) bool) {
	for changed := true; changed; {
		changed = false

		for key, current := range byArgs {
			if !redundant(current) {
				continue
			}

			for otherKey, other := range byArgs {
				if otherKey == key || argsDisjoint(current.args, other.args) ||
					!stricter(other, current) {
					continue
				}

				raised := current
				raised.args = other.args
				byArgs[otherKey] = raised
				changed = true
			}
		}
	}
}

// stricter reports whether the first clause applies a strictly more
// restrictive action than the second.
func stricter(first, second clause) bool {
	return !actionsEquivalent(first.action, second.action) &&
		actionsEquivalent(MoreRestrictive(first.action, second.action), first.action)
}

func defaultClause(profile *specs.LinuxSeccomp) *clause {
	return &clause{
		action:   profile.DefaultAction,
		errnoRet: merge.ClonePtr(profile.DefaultErrnoRet),
		args:     nil,
	}
}

// mergeProfileSyscalls merges the syscall entries of two profiles given the
// merged default clause. Entries equal to the merged default are elided.
func (m ruleMerger) mergeProfileSyscalls(
	left, right *specs.LinuxSeccomp,
	mergedDefault *clause,
) []specs.LinuxSyscall {
	leftDef := defaultClause(left)
	rightDef := defaultClause(right)
	leftRules := collectRules(left.Syscalls, leftDef)
	rightRules := collectRules(right.Syscalls, rightDef)

	names := slices.Sorted(maps.Keys(leftRules))

	for name := range rightRules {
		if _, ok := leftRules[name]; !ok {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	var result []specs.LinuxSyscall

	for _, name := range names {
		fallback, conditional := m.mergeRules(
			leftRules[name], rightRules[name], leftDef, rightDef,
		)
		fallback, conditional = m.finishRules(mergedDefault, fallback, conditional)

		if fallback != nil && !fallback.sameResult(*mergedDefault) {
			result = append(result, clauseToSyscall(name, *fallback))
		}

		for _, current := range conditional {
			result = append(result, clauseToSyscall(name, current))
		}
	}

	return result
}

// finishRules turns merged rules into emittable ones. A fallback equal to
// the merged default is elided, and conditional clauses are collapsed
// against whatever applies where they do not match: the fallback, or the
// merged default once the fallback is elided. A fallback that differs from
// the default only by errno is elided as well when a conditional clause with
// a different action remains, since keeping that clause is worth more than
// the errno value: an unconditional entry would force it to collapse.
// Clauses that share the fallback's action fold into it instead, so the
// leftmost errno survives.
func (m ruleMerger) finishRules(
	mergedDefault, fallback *clause, conditional []clause,
) (*clause, []clause) {
	switch {
	case fallback == nil || fallback.sameResult(*mergedDefault):
		fallback = nil
		conditional = m.collapseClauses(conditional, mergedDefault)
	case actionsEquivalent(fallback.action, mergedDefault.action):
		conditional = m.collapseClauses(conditional, fallback)

		if slices.ContainsFunc(conditional, func(current clause) bool {
			return !actionsEquivalent(current.action, fallback.action)
		}) {
			conditional = m.collapseClauses(conditional, mergedDefault)
			fallback = nil
		}
	default:
		conditional = m.collapseClauses(conditional, fallback)
	}

	return m.resolveMixed(fallback, conditional)
}

// mergeBareSyscalls merges two syscall lists that carry no profile default.
// Names present on one side only are dropped for intersection and kept for
// union.
func (m ruleMerger) mergeBareSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	leftRules := collectRules(left, nil)
	rightRules := collectRules(right, nil)

	names := slices.Sorted(maps.Keys(leftRules))

	if !m.intersect {
		for name := range rightRules {
			if _, ok := leftRules[name]; !ok {
				names = append(names, name)
			}
		}
	}

	var result []specs.LinuxSyscall

	for _, name := range names {
		leftRule, inLeft := leftRules[name]
		rightRule, inRight := rightRules[name]

		if m.intersect && (!inLeft || !inRight) {
			continue
		}

		fallback, conditional := m.mergeRules(leftRule, rightRule, nil, nil)
		fallback, conditional = m.resolveMixed(fallback, m.collapseClauses(conditional, fallback))

		if fallback != nil {
			result = append(result, clauseToSyscall(name, *fallback))
		}

		for _, current := range conditional {
			result = append(result, clauseToSyscall(name, current))
		}
	}

	return result
}

func clauseToSyscall(name string, current clause) specs.LinuxSyscall {
	return specs.LinuxSyscall{
		Names:    []string{name},
		Action:   current.action,
		ErrnoRet: merge.ClonePtr(current.errnoRet),
		Args:     slices.Clone(current.args),
	}
}
