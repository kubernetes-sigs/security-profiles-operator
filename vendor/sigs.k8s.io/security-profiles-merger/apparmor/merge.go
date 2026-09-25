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

package apparmor

import (
	"fmt"
	"slices"
	"strings"

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
)

// InputError is returned by Intersect and Union when one of the profiles
// they were given fails validation, naming its position among the arguments.
type InputError = spm.InputError

// Intersect merges multiple AppArmor profiles via intersection: the
// resulting profile permits an operation only if every input permits it.
// Capabilities and file access rules are intersected, and network
// permissions use AND semantics. This is the merge KEP-6061 defines for a
// CRI runtime combining an artifact with its baseline.
//
// A nil section or network boolean is treated as an explicit empty section
// or false, since to AppArmor an absent section denies everything it
// covers, and the result carries every section explicitly. Capability names
// are compared with ASCII case folding and returned upper-cased, which a
// consumer must lower-case before rendering them as rules (see
// CapabilityRules). A literal path survives where a glob of every other
// input matches it; the Filesystem merge section of the package
// documentation gives the rules for globs.
//
// More than two profiles are folded from left to right, and with patterns
// involved the result depends on that order, but every grouping is safe:
// the result permits only what every input permits. Matching paths against
// patterns is bounded, and past the budget a list keeps only the paths both
// sides spell alike, which permits no more than the exact intersection
// would (see the Cost bounds section).
//
// Each input is validated as the Validation section of the package
// documentation describes, and a failure is returned as an InputError
// naming the input.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectStrategy{})
}

// Union merges multiple AppArmor profiles via union: the resulting profile
// permits an operation if any input permits it. Capabilities and file
// access rules are combined, and network permissions use OR semantics. This
// is the merge the Security Profiles Operator uses to combine recorded
// profiles.
//
// A nil section defers to the other profile, which for a union grants the
// same as an empty one would. Capability names are upper-cased as they are
// by Intersect. A literal of one profile that a glob of the other covers is
// dropped, or takes the glob's permissions where the glob grants only part
// of them, so a write-only literal under a read-only glob becomes
// read-write; the Filesystem merge section of the package documentation has
// the details. The union of two profiles depends neither on their order
// nor on the order of their paths.
//
// Matching paths against patterns is bounded as it is for Intersect. Past
// the budget a list keeps every path of both sides with the permissions its
// own side grants it, which permits exactly what the reduced union permits
// (see the Cost bounds section). Inputs are validated as for Intersect.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionStrategy{})
}

type strategy interface {
	mergeStrings(left, right []string) []string
	mergePaths(left, right []string) []string
	mergeBool(left, right *bool) *bool
	mergeFilesystem(left, right *FilesystemRules) *FilesystemRules
	// prepare adjusts a normalized copy of an input before it is merged.
	prepare(profile *Profile)
}

func foldProfiles(profiles []*Profile, mergeOp strategy) (*Profile, error) {
	for idx, profile := range profiles {
		err := validateEmptyPathsInProfile(profile)
		if err != nil {
			return nil, &spm.InputError{Index: idx, Err: err}
		}
	}

	normalized := make([]*Profile, len(profiles))
	for idx, profile := range profiles {
		normalized[idx] = normalizeProfile(profile)
		deduplicateProfile(normalized[idx])
		canonicalizeAliases(normalized[idx])

		err := Validate(normalized[idx])
		if err != nil {
			return nil, &spm.InputError{Index: idx, Err: err}
		}
	}

	// Each profile now holds one spelling per rule, but two profiles may
	// hold different ones, and the merge compares paths as text.
	unifyAliasSpellings(normalized)

	// Preparing may drop paths, so it runs after validation, which must see
	// every path the caller passed.
	for _, profile := range normalized {
		mergeOp.prepare(profile)
	}

	result, err := merge.Fold(normalized, cloneProfile, func(a, b *Profile) (*Profile, error) {
		return mergeTwo(a, b, mergeOp), nil
	})
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}

	sortProfile(result)

	return result, nil
}

// canonicalizeAliases folds the paths of one list that spell the same rule
// into one entry, keeping the simplest spelling. Two such spellings differ
// only in escapes or repeated slashes the parser resolves, so they are one
// rule for one file, and the merge would otherwise carry both and match only
// one of them. Lists holding no such pair, which is every list of a profile
// written by hand, are left as they are.
//
// It runs on each input, not on the result. Two spellings in different
// categories are left alone: a profile naming one file twice that way fails
// the merge whether or not its spellings agree, which is what it does for an
// exact duplicate. The result needs no folding of its own, since
// unifyAliasSpellings has given every input the same spelling for a rule and
// the merge introduces no new one.
func canonicalizeAliases(profile *Profile) {
	mapPathLists(profile, foldAliasList)
}

// unifyAliasSpellings gives every profile the same spelling for a rule any
// of them holds, so that two profiles naming one file differently name it
// alike from here on. canonicalizeAliases folds the aliases within a
// profile, but it keeps a spelling that profile happens to hold, and the
// merge compares literal paths and glob patterns as text: without this, an
// intersection of "/etc/passwd" with an escaped spelling of the same file
// would drop a path both profiles grant, in the direction that silently
// costs a workload its access.
//
// The spelling kept is the simplest one some input holds (simplestSpelling),
// never one derived from the decoded name: a decoded name may hold a
// character a profile must escape, which ValidateArtifact rejects
// (ErrUnquotablePath), so deriving it could turn a loadable input into a
// result no consumer can spell. Rewriting a path to another input's spelling
// of the same rule cannot: it is a path an input already carried.
//
// It cannot make a profile hold one rule twice. Within a list, each profile
// holds one path per key already, and rewriting maps equal keys to one
// spelling, so the rewritten list has one path per key as well. Across the
// categories of one profile, Validate has just rejected two paths sharing a
// key, so no two categories can collapse onto one spelling here.
func unifyAliasSpellings(profiles []*Profile) {
	simplest := make(map[pathKey]string)

	for _, profile := range profiles {
		eachPathList(profile, func(paths []string) {
			for _, path := range paths {
				key := keyForPath(path)

				kept, ok := simplest[key]
				if !ok || simplestSpelling(path, kept) < 0 {
					simplest[key] = path
				}
			}
		})
	}

	for _, profile := range profiles {
		eachPathList(profile, func(paths []string) {
			for idx, path := range paths {
				paths[idx] = simplest[keyForPath(path)]
			}
		})
	}
}

// eachPathList calls visit with every list of paths a profile holds. The
// slices are visited in place, so a visitor may rewrite their elements.
func eachPathList(profile *Profile, visit func(paths []string)) {
	mapPathLists(profile, func(paths []string) []string {
		visit(paths)

		return paths
	})
}

// mapPathLists replaces every list of paths a profile holds with what apply
// returns for it. A section the profile omits holds no list.
func mapPathLists(profile *Profile, apply func(paths []string) []string) {
	if profile.Executable != nil {
		profile.Executable.AllowedExecutables = apply(profile.Executable.AllowedExecutables)
		profile.Executable.AllowedLibraries = apply(profile.Executable.AllowedLibraries)
	}

	if profile.Filesystem != nil {
		profile.Filesystem.ReadOnlyPaths = apply(profile.Filesystem.ReadOnlyPaths)
		profile.Filesystem.WriteOnlyPaths = apply(profile.Filesystem.WriteOnlyPaths)
		profile.Filesystem.ReadWritePaths = apply(profile.Filesystem.ReadWritePaths)
	}
}

// hasAliases reports whether two different paths of a list spell one rule.
func hasAliases(paths []string) bool {
	seen := make(map[pathKey]string, len(paths))

	for _, path := range paths {
		key := keyForPath(path)

		if earlier, ok := seen[key]; ok && earlier != path {
			return true
		}

		seen[key] = path
	}

	return false
}

// foldAliasList returns the list with one spelling per rule.
func foldAliasList(paths []string) []string {
	if !hasAliases(paths) {
		return paths
	}

	sorted := slices.Clone(paths)
	slices.SortFunc(sorted, simplestSpelling)

	seen := make(map[pathKey]struct{}, len(sorted))
	folded := make([]string, 0, len(sorted))

	for _, path := range sorted {
		key := keyForPath(path)

		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		folded = append(folded, path)
	}

	return folded
}

// simplestSpelling orders two spellings of one rule: a spelling a consumer
// can render as a rule first, since one of the spellings may leave a
// character escaped that must stay escaped (ErrUnquotablePath), then the
// shorter one, which is the one written without escapes the parser only has
// to resolve, and spellings of one length by text, so that which one a merge
// keeps never depends on the order the paths arrive in.
func simplestSpelling(left, right string) int {
	if leftBad, rightBad := hasUnquotableChar(left), hasUnquotableChar(right); leftBad != rightBad {
		if rightBad {
			return -1
		}

		return 1
	}

	if len(left) != len(right) {
		return len(left) - len(right)
	}

	return strings.Compare(left, right)
}

func sortProfile(profile *Profile) {
	eachPathList(profile, slices.Sort[[]string])

	if profile.Capabilities != nil {
		slices.Sort(profile.Capabilities.AllowedCapabilities)
	}
}

func mergeTwo(left, right *Profile, mergeStrategy strategy) *Profile {
	return &Profile{
		Executable:   mergeExecutable(left.Executable, right.Executable, mergeStrategy),
		Filesystem:   mergeFilesystem(left.Filesystem, right.Filesystem, mergeStrategy),
		Network:      mergeNetwork(left.Network, right.Network, mergeStrategy),
		Capabilities: mergeCapabilities(left.Capabilities, right.Capabilities, mergeStrategy),
	}
}

func mergeOptional[T any](
	left, right *T,
	cloneFn func(*T) *T,
	mergeFn func(*T, *T) *T,
) *T {
	if left == nil && right == nil {
		return nil
	}

	if left == nil {
		return cloneFn(right)
	}

	if right == nil {
		return cloneFn(left)
	}

	return mergeFn(left, right)
}

func mergeExecutable(left, right *ExecutableRules, mergeStrategy strategy) *ExecutableRules {
	return mergeOptional(
		left,
		right,
		cloneExecutable,
		func(lhs, rhs *ExecutableRules) *ExecutableRules {
			return &ExecutableRules{
				AllowedExecutables: mergeStrategy.mergePaths(
					lhs.AllowedExecutables,
					rhs.AllowedExecutables,
				),
				AllowedLibraries: mergeStrategy.mergePaths(
					lhs.AllowedLibraries,
					rhs.AllowedLibraries,
				),
			}
		},
	)
}

func mergeFilesystem(left, right *FilesystemRules, mergeStrategy strategy) *FilesystemRules {
	return mergeOptional(
		left,
		right,
		cloneFilesystem,
		func(lhs, rhs *FilesystemRules) *FilesystemRules {
			return mergeStrategy.mergeFilesystem(lhs, rhs)
		},
	)
}

func mergeNetwork(left, right *NetworkRules, mergeStrategy strategy) *NetworkRules {
	return mergeOptional(left, right, cloneNetwork, func(lhs, rhs *NetworkRules) *NetworkRules {
		result := &NetworkRules{
			AllowRaw:  mergeStrategy.mergeBool(lhs.AllowRaw, rhs.AllowRaw),
			Protocols: nil,
		}

		switch {
		case lhs.Protocols != nil && rhs.Protocols != nil:
			result.Protocols = &AllowedProtocols{
				AllowTCP: mergeStrategy.mergeBool(lhs.Protocols.AllowTCP, rhs.Protocols.AllowTCP),
				AllowUDP: mergeStrategy.mergeBool(lhs.Protocols.AllowUDP, rhs.Protocols.AllowUDP),
			}
		case lhs.Protocols != nil:
			result.Protocols = cloneProtocols(lhs.Protocols)
		case rhs.Protocols != nil:
			result.Protocols = cloneProtocols(rhs.Protocols)
		}

		return result
	})
}

func mergeCapabilities(left, right *CapabilityRules, mergeStrategy strategy) *CapabilityRules {
	return mergeOptional(
		left,
		right,
		cloneCapabilities,
		func(lhs, rhs *CapabilityRules) *CapabilityRules {
			return &CapabilityRules{
				AllowedCapabilities: mergeStrategy.mergeStrings(
					lhs.AllowedCapabilities,
					rhs.AllowedCapabilities,
				),
			}
		},
	)
}

// intersectStrategy implements intersection (AND) semantics.
type intersectStrategy struct{}

// prepare makes omitted sections explicit, since to AppArmor an absent
// section denies everything it covers and the intersection must not permit
// more than that input does.
//
// It also drops the glob patterns that match nothing, as a pairwise
// intersection does, so that intersecting a single profile gives what
// intersecting it with itself gives.
func (intersectStrategy) prepare(profile *Profile) {
	populateEmpty(profile)
	mapPathLists(profile, dropUnusableGlobs)
}

// populateEmpty replaces every nil section of the profile with an explicit
// empty one and every nil network boolean with false, which is what an
// absent section means to AppArmor.
func populateEmpty(profile *Profile) {
	if profile.Executable == nil {
		profile.Executable = &ExecutableRules{AllowedExecutables: nil, AllowedLibraries: nil}
	}

	if profile.Filesystem == nil {
		profile.Filesystem = &FilesystemRules{
			ReadOnlyPaths: nil, WriteOnlyPaths: nil, ReadWritePaths: nil,
		}
	}

	if profile.Capabilities == nil {
		profile.Capabilities = &CapabilityRules{AllowedCapabilities: nil}
	}

	if profile.Network == nil {
		profile.Network = &NetworkRules{AllowRaw: nil, Protocols: nil}
	}

	if profile.Network.AllowRaw == nil {
		profile.Network.AllowRaw = new(bool)
	}

	if profile.Network.Protocols == nil {
		profile.Network.Protocols = &AllowedProtocols{AllowTCP: nil, AllowUDP: nil}
	}

	if profile.Network.Protocols.AllowTCP == nil {
		profile.Network.Protocols.AllowTCP = new(bool)
	}

	if profile.Network.Protocols.AllowUDP == nil {
		profile.Network.Protocols.AllowUDP = new(bool)
	}
}

func (intersectStrategy) mergeStrings(left, right []string) []string {
	return merge.IntersectSlice(left, right)
}

// mergePaths intersects two plain path lists through the permission merge,
// reading every path as granting one permission, so that the executable
// lists and the filesystem rules are narrowed, budgeted and fallen back by
// one implementation.
func (intersectStrategy) mergePaths(left, right []string) []string {
	return permittedPaths(intersectPerms(readPerms(left), readPerms(right)))
}

// mergeBool never sees nil, since prepare populated every boolean.
func (intersectStrategy) mergeBool(left, right *bool) *bool {
	return mergeBoolPtr(left, right, func(lhs, rhs bool) bool { return lhs && rhs })
}

// mergeBoolPtr combines two optional booleans, letting a nil one defer to
// the other.
func mergeBoolPtr(left, right *bool, combine func(lhs, rhs bool) bool) *bool {
	if left == nil {
		return merge.ClonePtr(right)
	}

	if right == nil {
		return merge.ClonePtr(left)
	}

	val := combine(*left, *right)

	return &val
}

func (intersectStrategy) mergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	return collapseFsPerms(intersectPerms(expandFsPerms(left), expandFsPerms(right)))
}

// intersectPerms returns the permissions both sides grant, per path.
func intersectPerms(leftPerms, rightPerms map[string]fsPermission) map[string]fsPermission {
	merged := make(map[string]fsPermission)

	// Literal-vs-literal intersection via map lookup: O(n+m).
	for path, leftPerm := range leftPerms {
		if IsGlobPattern(path) {
			continue
		}

		if rightPerm, ok := rightPerms[path]; ok {
			intersected := leftPerm.intersect(rightPerm)
			if intersected.read || intersected.write {
				merged[path] = intersected
			}
		}
	}

	// Glob entries need matching against the other side. Both directions go
	// through a prefix index rather than a pairwise scan, so a profile with
	// many paths does not turn the merge quadratic. Patterns sharing one
	// prefix land in one bucket, though, which the index cannot split, so
	// the work is bounded as well: past the budget only the patterns both
	// sides list alike are kept, next to the literals both sides list, which
	// permits no more than matching them would.
	leftSide := buildFsSide(leftPerms)
	rightSide := buildFsSide(rightPerms)

	if exceedsPairBudget(leftSide.size(), rightSide.size()) {
		addVerbatimGlobs(leftSide, rightSide, merged)

		return merged
	}

	matchFsLiterals(leftSide.literals, rightSide, merged)
	matchFsLiterals(rightSide.literals, leftSide, merged)
	matchFsGlobs(leftSide, rightSide, merged)

	return merged
}

// addFsMatch records the permissions two matching entries share under key,
// combining them with what an earlier match already granted there.
func addFsMatch(merged map[string]fsPermission, key string, perm fsPermission) {
	if !perm.read && !perm.write {
		return
	}

	if existing, ok := merged[key]; ok {
		merged[key] = existing.union(perm)

		return
	}

	merged[key] = perm
}

// matchFsLiterals intersects every literal path with the globs of the other
// side that match it, keyed by the literal, which is the narrower path.
func matchFsLiterals(
	literals []fsPathEntry, other fsSide, merged map[string]fsPermission,
) {
	for _, literal := range literals {
		name := literal.matcher.literal

		other.byPrefix.candidates(name, func(pattern string) bool {
			entry := other.globs[pattern]
			if entry.matcher.matches(name) {
				addFsMatch(merged, literal.path, literal.perm.intersect(entry.perm))
			}

			return false
		})
	}
}

// matchFsGlobs intersects globs present on both sides, and globs one side
// covers with the "**" expansion of a containing prefix. The narrower of the
// two patterns keys the result, as it is the one both sides permit.
func matchFsGlobs(left, right fsSide, merged map[string]fsPermission) {
	addVerbatimGlobs(left, right, merged)

	for _, entry := range left.globs {
		narrowFsGlob(entry, right, merged)
	}

	// Both narrowing directions run for every glob, including one present on
	// both sides: the loop above records what the right side expands over,
	// which says nothing about what the left side expands over.
	for _, entry := range right.globs {
		narrowFsGlob(entry, left, merged)
	}
}

// addVerbatimGlobs intersects the patterns both sides list alike, which
// needs no matching: a pattern both sides list is permitted by both whatever
// it matches.
func addVerbatimGlobs(left, right fsSide, merged map[string]fsPermission) {
	for pattern, entry := range left.globs {
		if other, both := right.globs[pattern]; both {
			addFsMatch(merged, pattern, entry.perm.intersect(other.perm))
		}
	}
}

// narrowFsGlob intersects a glob with every "<prefix>**" pattern of the
// other side that expands over it (see globMatcher.expandedBy), keyed by the
// glob, which is the narrower of the two.
func narrowFsGlob(entry fsPathEntry, other fsSide, merged map[string]fsPermission) {
	other.starStar.candidates(entry.matcher.prefix, func(pattern string) bool {
		base := other.globs[pattern]
		if entry.matcher.expandedBy(base.matcher) {
			addFsMatch(merged, entry.path, entry.perm.intersect(base.perm))
		}

		return false
	})
}

// unionStrategy implements union (OR) semantics.
type unionStrategy struct{}

// prepare leaves omitted sections alone: for a union, a nil section and an
// empty one both yield the other side's grants.
func (unionStrategy) prepare(*Profile) {}

func (unionStrategy) mergeStrings(left, right []string) []string {
	return merge.UnionSlice(left, right)
}

func (unionStrategy) mergePaths(left, right []string) []string {
	return permittedPaths(unionPerms(readPerms(left), readPerms(right)))
}

func (unionStrategy) mergeBool(left, right *bool) *bool {
	return mergeBoolPtr(left, right, func(lhs, rhs bool) bool { return lhs || rhs })
}

func (unionStrategy) mergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	return collapseFsPerms(unionPerms(expandFsPerms(left), expandFsPerms(right)))
}

// readPerms maps every path of a list to the read permission, so that a
// list without categories can be merged like filesystem rules.
func readPerms(paths []string) map[string]fsPermission {
	perms := make(map[string]fsPermission, len(paths))

	for _, path := range paths {
		perms[path] = fsPermission{read: true, write: false}
	}

	return perms
}

// permittedPaths returns the paths of a permission map, sorted.
func permittedPaths(perms map[string]fsPermission) []string {
	if len(perms) == 0 {
		return nil
	}

	paths := make([]string, 0, len(perms))

	for path := range perms {
		paths = append(paths, path)
	}

	slices.Sort(paths)

	return paths
}

// unionPerms merges the paths of two profiles. A glob keeps the permissions
// either profile grants it; globs never prune globs. A literal both profiles
// list keeps what they list. A literal only one profile lists is dropped when
// the other profile's globs grant everything it grants, and otherwise also
// takes what those globs grant it, so that a read-only literal under a
// write-only glob becomes read-write. A profile's own globs never prune its
// own literals. Each path's result depends only on the two profiles, not on
// their order or on the order of the paths within them.
func unionPerms(left, right map[string]fsPermission) map[string]fsPermission {
	merged := make(map[string]fsPermission, len(left)+len(right))

	leftSide := buildFsSide(left)
	rightSide := buildFsSide(right)

	if exceedsPairBudget(leftSide.size(), rightSide.size()) {
		return unionVerbatim(left, right)
	}

	addUnionLiterals(leftSide.literals, right, rightSide, merged)
	addUnionLiterals(rightSide.literals, left, leftSide, merged)

	for _, perms := range []map[string]fsPermission{left, right} {
		for path, perm := range perms {
			if IsGlobPattern(path) {
				merged[path] = merged[path].union(perm)
			}
		}
	}

	return merged
}

// unionVerbatim returns every path of both sides with the permissions they
// grant it, the result a union falls back to past its pair budget. It
// permits what the reduced union permits: a literal the reduction drops
// grants no more than a pattern of the other side grants, and one the
// reduction raises is raised by such a pattern, and either way that pattern
// is kept here too.
func unionVerbatim(left, right map[string]fsPermission) map[string]fsPermission {
	merged := make(map[string]fsPermission, len(left)+len(right))

	for _, perms := range []map[string]fsPermission{left, right} {
		for path, perm := range perms {
			merged[path] = merged[path].union(perm)
		}
	}

	return merged
}

// addUnionLiterals records the literals of one profile as unionPerms
// describes, given the other profile's paths and globs.
func addUnionLiterals(
	literals []fsPathEntry, otherPerms map[string]fsPermission, other fsSide,
	merged map[string]fsPermission,
) {
	for _, literal := range literals {
		perm := literal.perm

		if _, listed := otherPerms[literal.path]; !listed {
			granted := other.grants(literal.matcher.literal)
			if granted.union(perm) == granted {
				continue
			}

			perm = perm.union(granted)
		}

		merged[literal.path] = merged[literal.path].union(perm)
	}
}

// fsPermission tracks read/write permissions for a single path.
type fsPermission struct {
	read  bool
	write bool
}

func (perm fsPermission) intersect(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read && other.read,
		write: perm.write && other.write,
	}
}

func (perm fsPermission) union(other fsPermission) fsPermission {
	return fsPermission{
		read:  perm.read || other.read,
		write: perm.write || other.write,
	}
}

func expandFsPerms(rules *FilesystemRules) map[string]fsPermission {
	capacity := len(rules.ReadOnlyPaths) + len(rules.WriteOnlyPaths) + len(rules.ReadWritePaths)
	perms := make(map[string]fsPermission, capacity)

	for _, path := range rules.ReadOnlyPaths {
		entry := perms[path]
		entry.read = true
		perms[path] = entry
	}

	for _, path := range rules.WriteOnlyPaths {
		entry := perms[path]
		entry.write = true
		perms[path] = entry
	}

	for _, path := range rules.ReadWritePaths {
		entry := perms[path]
		entry.read = true
		entry.write = true
		perms[path] = entry
	}

	return perms
}

func collapseFsPerms(perms map[string]fsPermission) *FilesystemRules {
	var readOnly, writeOnly, readWrite []string

	for path, perm := range perms {
		switch {
		case perm.read && perm.write:
			readWrite = append(readWrite, path)
		case perm.read:
			readOnly = append(readOnly, path)
		case perm.write:
			writeOnly = append(writeOnly, path)
		}
	}

	return &FilesystemRules{
		ReadOnlyPaths:  readOnly,
		WriteOnlyPaths: writeOnly,
		ReadWritePaths: readWrite,
	}
}

func cloneProfile(profile *Profile) *Profile {
	clone := &Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	if profile.Executable != nil {
		clone.Executable = cloneExecutable(profile.Executable)
	}

	if profile.Filesystem != nil {
		clone.Filesystem = cloneFilesystem(profile.Filesystem)
	}

	if profile.Network != nil {
		clone.Network = cloneNetwork(profile.Network)
	}

	if profile.Capabilities != nil {
		clone.Capabilities = cloneCapabilities(profile.Capabilities)
	}

	return clone
}

func cloneExecutable(exec *ExecutableRules) *ExecutableRules {
	return &ExecutableRules{
		AllowedExecutables: slices.Clone(exec.AllowedExecutables),
		AllowedLibraries:   slices.Clone(exec.AllowedLibraries),
	}
}

func cloneFilesystem(fsRules *FilesystemRules) *FilesystemRules {
	return &FilesystemRules{
		ReadOnlyPaths:  slices.Clone(fsRules.ReadOnlyPaths),
		WriteOnlyPaths: slices.Clone(fsRules.WriteOnlyPaths),
		ReadWritePaths: slices.Clone(fsRules.ReadWritePaths),
	}
}

func cloneNetwork(network *NetworkRules) *NetworkRules {
	clone := &NetworkRules{
		AllowRaw:  merge.ClonePtr(network.AllowRaw),
		Protocols: nil,
	}

	if network.Protocols != nil {
		clone.Protocols = cloneProtocols(network.Protocols)
	}

	return clone
}

func cloneProtocols(proto *AllowedProtocols) *AllowedProtocols {
	return &AllowedProtocols{
		AllowTCP: merge.ClonePtr(proto.AllowTCP),
		AllowUDP: merge.ClonePtr(proto.AllowUDP),
	}
}

func cloneCapabilities(caps *CapabilityRules) *CapabilityRules {
	return &CapabilityRules{
		AllowedCapabilities: slices.Clone(caps.AllowedCapabilities),
	}
}

func normalizeProfile(profile *Profile) *Profile {
	result := cloneProfile(profile)

	mapPathLists(result, normalizePaths)

	if result.Capabilities != nil {
		result.Capabilities.AllowedCapabilities = normalizeCapabilities(
			result.Capabilities.AllowedCapabilities,
		)
	}

	return result
}

func normalizeCapabilities(caps []string) []string {
	if caps == nil {
		return nil
	}

	result := make([]string, len(caps))
	for idx, c := range caps {
		result[idx] = asciiUpper(c)
	}

	return result
}

func deduplicateProfile(profile *Profile) {
	mapPathLists(profile, merge.DeduplicateSlice[string])

	if profile.Capabilities != nil {
		profile.Capabilities.AllowedCapabilities = merge.DeduplicateSlice(
			profile.Capabilities.AllowedCapabilities,
		)
	}
}

// normalizePath collapses repeated slashes, as apparmor_parser does before
// compiling a rule, counting an escaped slash as one (see
// filterRawSlashes). It keeps a trailing slash, which distinguishes a
// directory rule from a file rule, and leaves "." and ".." components alone:
// the kernel hands AppArmor canonical paths, so a rule containing them
// matches nothing, and resolving them would make the rule grant more.
func normalizePath(path string) string {
	return filterRawSlashes(path)
}

func normalizePaths(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))

	for idx, p := range paths {
		result[idx] = normalizePath(p)
	}

	return result
}
