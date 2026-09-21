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
	"regexp"
	"slices"
	"strings"
	"sync"
)

var (
	// globCacheMu protects globCacheEntries.
	globCacheMu sync.RWMutex

	// globCacheEntries stores analyzed patterns keyed by pattern.
	globCacheEntries = make(map[string]*globMatcher)

	// globCacheBytes is the total pattern length globCacheEntries holds. A
	// compiled program grows with its pattern, so bounding the patterns
	// bounds what the cache retains, which an entry count alone does not:
	// maxGlobCacheEntries patterns of maxGlobPatternLen would be megabytes.
	globCacheBytes int
)

const (
	maxGlobPatternLen     = MaxPathLen
	maxGlobAlternatives   = 100
	maxGlobCacheEntries   = 1024
	maxGlobCacheBytes     = 256 << 10
	globCacheEvictDivisor = 4

	// maxMergePathPairs bounds the pattern comparisons merging one category
	// of paths may cost. Matching a literal against a pattern costs a
	// regular expression evaluation, and every literal of one side may have
	// to be tried against every pattern of the other, so the work grows with
	// the product of the two counts. The prefix index removes most of those
	// pairs when the patterns are rooted in different directories, but
	// patterns sharing one prefix all land in the same bucket and the
	// product is then what the merge pays: without a bound, two profiles of
	// a few thousand paths under one directory take minutes, and nothing
	// stops a profile from being larger still.
	//
	// Past the bound the merge falls back to a result that needs no
	// matching, conservative for an intersection and equivalent for a union
	// (see addVerbatimGlobs and unionVerbatim). The bound admits two
	// profiles of MaxArtifactPaths paths each, so a profile a runtime
	// accepts is merged exactly.
	maxMergePathPairs = 1 << 20
	// maxMergePathWork bounds the same matching by the bytes it compares,
	// not only by the number of comparisons. One comparison runs a pattern's
	// program over a name, so it costs about the length of the pattern plus
	// the length of the name, and a profile chooses both: two profiles of a
	// quarter megabyte, well inside MaxArtifactPaths and the pair bound,
	// took two minutes to intersect while allocating almost nothing. The
	// budget is the pair bound at the length of a path a profile names.
	maxMergePathWork = maxMergePathPairs * typicalPathLen
	// typicalPathLen is the path length the pair bound assumes.
	typicalPathLen = 64
)

// patternSyntax holds the bytes that make a path need analysis: glob
// metacharacters, the escape character, and NUL, which no profile can hold.
const patternSyntax = "\\*?[]{}\x00"

// globStatus says whether a glob pattern can be matched.
type globStatus int

const (
	// globUsable is a pattern the matcher models exactly.
	globUsable globStatus = iota
	// globTooComplex is a pattern past the matcher's size or alternative
	// limits. AppArmor may accept it, but this package matches nothing
	// with it.
	globTooComplex
	// globInvalid is a pattern apparmor_parser rejects, or accepts with a
	// meaning this package does not model. It matches nothing.
	globInvalid
)

// globMatcher is the analyzed form of a path.
type globMatcher struct {
	// expr matches the latin1-mapped names the pattern covers. It is nil
	// for a literal and for a pattern that matches nothing.
	expr   *regexp.Regexp
	kind   patternKind
	status globStatus
	// literal holds the bytes of the literal text before the first glob
	// token, which every matched name starts with. For a literal path it
	// is the file name the path denotes.
	literal string
	// prefix is literal up to and including its last "/", or "". It is
	// the key the prefix index files a glob under.
	prefix string
	// starStar reports a usable pattern that is its literal prefix
	// followed by "**", and nothing else.
	starStar bool
}

// usable reports whether the matcher can match anything.
func (matcher *globMatcher) usable() bool {
	return matcher.expr != nil
}

// matches reports whether the pattern covers the file name.
func (matcher *globMatcher) matches(name string) bool {
	return matcher.expr != nil && matcher.expr.MatchString(latin1(name))
}

// expandedBy reports whether the "**" pattern base grants every canonical path
// the glob matches, so that intersecting the two leaves the glob. base
// matches its literal prefix P followed by at least one character that is
// not "/". Every name the glob matches starts with the glob's prefix, which
// starts with P, so the only canonical name the glob may match and base may
// not is P itself. The guarantee holds over canonical paths only: absolute,
// without "//", "." or ".." components, which are the only names the kernel
// hands AppArmor. A glob whose literal prefix holds "//" (spelled with an
// escaped slash, as in "/etc/\/foo/*") matches no canonical path, and is
// never narrowed. A "/" after a "/" spelled by an alternation or a class,
// as in "/etc/{\/a,b}" or "/etc/[/]x", is not detected: such a glob may
// match a name with "//" that base does not, but no such name reaches
// AppArmor. A base with an empty prefix is never used, since a relative
// pattern cannot be loaded.
func (matcher *globMatcher) expandedBy(base *globMatcher) bool {
	if !base.starStar || base.prefix == "" || !matcher.usable() ||
		!strings.HasPrefix(matcher.prefix, base.prefix) ||
		strings.Contains(matcher.prefix, "//") {
		return false
	}

	return matcher.prefix != base.prefix || !matcher.matches(base.prefix)
}

// literalMatcher is the analysis of a path without pattern syntax.
func literalMatcher(path string) *globMatcher {
	name := filterSlashes(path)

	return &globMatcher{
		expr:     nil,
		kind:     kindLiteral,
		status:   globUsable,
		literal:  name,
		prefix:   name[:strings.LastIndexByte(name, '/')+1],
		starStar: false,
	}
}

// analyzePattern runs a path through the parser port and compiles the
// resulting regex, unless compile is false.
func analyzePattern(pattern string, compile bool) *globMatcher {
	conv := convertPattern(filterSlashes(decodeEscapes(pattern)))

	matcher := &globMatcher{
		expr:     nil,
		kind:     conv.kind,
		status:   globInvalid,
		literal:  "",
		prefix:   "",
		starStar: false,
	}

	if conv.kind == kindInvalid {
		return matcher
	}

	matcher.literal = literalBytes(conv.regex[:conv.literalEnd])
	matcher.prefix = matcher.literal[:strings.LastIndexByte(matcher.literal, '/')+1]

	if conv.kind == kindLiteral {
		matcher.status = globUsable

		return matcher
	}

	if !compile || conv.alternatives > maxGlobAlternatives {
		matcher.status = globTooComplex

		return matcher
	}

	fragment, ok := translateRegex(conv.regex)
	if !ok {
		return matcher
	}

	expr, err := regexp.Compile(`^` + fragment + `$`)
	if err != nil {
		matcher.status = globTooComplex

		return matcher
	}

	matcher.expr = expr
	matcher.status = globUsable
	matcher.starStar = conv.starStarOnly

	return matcher
}

// matcherFor returns the analysis of a path, caching it for paths with
// pattern syntax. A path past the length limit is analyzed without being
// compiled or cached: it matches nothing, and caching it would evict the
// patterns worth keeping.
func matcherFor(path string) *globMatcher {
	if !strings.ContainsAny(path, patternSyntax) {
		return literalMatcher(path)
	}

	if len(path) > maxGlobPatternLen {
		return analyzePattern(path, false)
	}

	globCacheMu.RLock()

	if cached, ok := globCacheEntries[path]; ok {
		globCacheMu.RUnlock()

		return cached
	}

	globCacheMu.RUnlock()

	analyzed := analyzePattern(path, true)

	globCacheMu.Lock()
	defer globCacheMu.Unlock()

	if cached, ok := globCacheEntries[path]; ok {
		return cached
	}

	evictGlobCache(len(path))

	globCacheEntries[path] = analyzed
	globCacheBytes += len(path)

	return analyzed
}

// evictGlobCache makes room for a pattern of the given length, dropping
// entries until the cache is under both its entry and byte bounds. Callers
// hold globCacheMu.
func evictGlobCache(incoming int) {
	overCount := len(globCacheEntries) >= maxGlobCacheEntries
	overBytes := globCacheBytes+incoming > maxGlobCacheBytes

	if !overCount && !overBytes {
		return
	}

	// An entry-count overflow evicts a quarter of the cache at once, so the
	// next insertions do not overflow again. A byte overflow evicts only
	// until the incoming pattern fits: the byte bound holds far fewer than a
	// quarter of the entry bound's worth of long patterns, so a fixed quota
	// would empty the cache every time.
	quota := 0
	if overCount {
		quota = maxGlobCacheEntries / globCacheEvictDivisor
	}

	for key := range globCacheEntries {
		if quota <= 0 && globCacheBytes+incoming <= maxGlobCacheBytes {
			break
		}

		delete(globCacheEntries, key)
		globCacheBytes -= len(key)
		quota--
	}
}

// IsGlobPattern reports whether the path is a pattern rather than the name
// of a single file: whether it contains AppArmor glob tokens ("*", "**",
// "?", character classes "[...]", or alternations "{a,b}"), or pattern
// syntax apparmor_parser rejects, such as an unbalanced bracket or brace or
// a trailing backslash. Backslash-escaped characters are literals. The
// merge functions treat a rejected pattern as matching nothing.
func IsGlobPattern(path string) bool {
	return strings.ContainsAny(path, patternSyntax) && matcherFor(path).kind != kindLiteral
}

// forEachAncestor calls visit with every literal prefix a glob pattern could
// have and still match name: the empty prefix, which belongs to patterns
// starting with a glob token, and every directory prefix of name. A glob's
// prefix is either empty or ends in "/" (see globMatcher.prefix), so this is
// exactly the set of prefixes name starts with. It stops when visit returns
// true, which it then reports.
func forEachAncestor(name string, visit func(prefix string) bool) bool {
	if visit("") {
		return true
	}

	for idx := range len(name) {
		if name[idx] == '/' && visit(name[:idx+1]) {
			return true
		}
	}

	return false
}

// pathKey identifies the rule a path spells, so that two spellings of one
// rule compare equal. A path without pattern syntax is identified by the
// name it denotes, with repeated slashes collapsed and escape sequences
// resolved, since apparmor_parser resolves them before it compiles the rule:
// "/a/b" and `/a/\b` are one rule for one file. A pattern is identified by
// the regular expression it compiles to, which two spellings of one pattern
// share, and by its text when it compiles to nothing, since patterns that
// match nothing are not thereby the same rule.
type pathKey struct {
	glob bool
	text string
}

// keyForPath returns the identity of a path.
func keyForPath(path string) pathKey {
	matcher := matcherFor(path)

	switch {
	case matcher.kind == kindLiteral:
		return pathKey{glob: false, text: matcher.literal}
	case matcher.expr != nil:
		return pathKey{glob: true, text: matcher.expr.String()}
	default:
		return pathKey{glob: true, text: path}
	}
}

// exceedsPairBudget reports whether matching two sides against each other
// would cost more comparisons than maxMergePathPairs. The literals of each
// side are matched against the patterns of the other, and the patterns of
// each side against the "**" patterns of the other, which costs one
// comparison per pair as well. Counting the products rather than the paths
// keeps a profile of many literals and no patterns, which needs no matching
// at all, inside the budget whatever its size.
// The counts are widened to uint64 first: they come from untrusted profiles,
// and on a 32-bit platform their products overflow an int at roughly 27k
// paths a side, which would turn the budget off exactly for the inputs it
// exists for. Only ValidateArtifact bounds the path count, and the merge
// runs Validate, so an unvalidated profile reaches this directly.
func exceedsPairBudget(
	leftLiterals, leftGlobs, rightLiterals, rightGlobs, longest int,
) bool {
	pairs := pathCount(leftLiterals)*pathCount(rightGlobs) +
		pathCount(rightLiterals)*pathCount(leftGlobs) +
		pathCount(leftGlobs)*pathCount(rightGlobs)

	if pairs > maxMergePathPairs {
		return true
	}

	// longest bounds both the pattern and the name of every pair. At or
	// below the assumed length, a pair costs no more than the pair bound
	// already allows for.
	if longest <= typicalPathLen {
		return false
	}

	return pairs*pathCount(longest) > maxMergePathWork
}

// pathCount widens a count of paths for the arithmetic above. Every count it
// is given is the length of a slice or a map, so the conversion cannot wrap.
func pathCount(count int) uint64 {
	//nolint:gosec // a length is never negative
	return uint64(count)
}

// prefixIndex groups patterns by a literal prefix so that a candidate is
// tested only against the patterns whose prefix it starts with, rather than
// against every pattern. Without it, matching n paths against m globs costs
// n*m regex evaluations, which a profile with many paths turns into the
// dominant cost of a merge.
type prefixIndex map[string][]string

func (index prefixIndex) add(prefix, pattern string) {
	index[prefix] = append(index[prefix], pattern)
}

// candidates calls visit for every pattern whose prefix name starts with,
// stopping early when visit returns true.
func (index prefixIndex) candidates(name string, visit func(pattern string) bool) {
	if len(index) == 0 {
		return
	}

	forEachAncestor(name, func(prefix string) bool {
		return slices.ContainsFunc(index[prefix], visit)
	})
}

// addStarStar files a "**" pattern under its prefix, if it is one.
func (index prefixIndex) addStarStar(pattern string, matcher *globMatcher) {
	if matcher.starStar && matcher.prefix != "" {
		index.add(matcher.prefix, pattern)
	}
}

type fsPathEntry struct {
	path    string
	perm    fsPermission
	matcher *globMatcher
}

// fsSide holds one side of a filesystem intersection, split into literal
// entries and glob entries, with the glob entries indexed for matching.
type fsSide struct {
	literals []fsPathEntry
	globs    map[string]fsPathEntry
	// byPrefix indexes every glob by the literal prefix a path must start
	// with to match it.
	byPrefix prefixIndex
	// starStar indexes the "**" globs, the only ones that can narrow
	// another glob.
	starStar prefixIndex
	// longest is the length of the longest path of the side.
	longest int
}

// grants returns the permissions the globs of the side grant the file name.
func (side fsSide) grants(name string) fsPermission {
	var granted fsPermission

	side.byPrefix.candidates(name, func(pattern string) bool {
		entry := side.globs[pattern]
		if entry.matcher.matches(name) {
			granted = granted.union(entry.perm)
		}

		return granted.read && granted.write
	})

	return granted
}

func buildFsSide(perms map[string]fsPermission) fsSide {
	side := fsSide{
		literals: make([]fsPathEntry, 0, len(perms)),
		globs:    make(map[string]fsPathEntry, len(perms)),
		byPrefix: make(prefixIndex),
		starStar: make(prefixIndex),
		longest:  0,
	}

	for path, perm := range perms {
		matcher := matcherFor(path)

		side.longest = max(side.longest, len(path))

		if matcher.kind == kindLiteral {
			side.literals = append(side.literals, fsPathEntry{
				path: path, perm: perm, matcher: matcher,
			})

			continue
		}

		if !matcher.usable() {
			// A pattern that matches nothing cannot contribute to an
			// intersection.
			continue
		}

		side.globs[path] = fsPathEntry{path: path, perm: perm, matcher: matcher}
		side.byPrefix.add(matcher.prefix, path)
		side.starStar.addStarStar(path, matcher)
	}

	return side
}

// dropUnusableGlobs returns the paths without the glob patterns that match
// nothing, reusing the slice when there are none. It returns nil when it
// drops every path, as a pairwise intersection does.
func dropUnusableGlobs(paths []string) []string {
	unusable := func(path string) bool {
		return IsGlobPattern(path) && !matcherFor(path).usable()
	}

	if !slices.ContainsFunc(paths, unusable) {
		return paths
	}

	kept := slices.DeleteFunc(slices.Clone(paths), unusable)
	if len(kept) == 0 {
		return nil
	}

	return kept
}
