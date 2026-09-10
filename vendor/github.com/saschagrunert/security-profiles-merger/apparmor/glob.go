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
	// neverMatchRe is a fallback regex that matches nothing.
	neverMatchRe = regexp.MustCompile(`^(?:$.)$`)

	// globCacheMu protects globCacheEntries.
	globCacheMu sync.RWMutex

	// globCacheEntries stores compiled glob regexes keyed by pattern.
	globCacheEntries = make(map[string]*regexp.Regexp)
)

const (
	maxGlobPatternLen     = 4096
	maxGlobAlternatives   = 100
	maxGlobCacheEntries   = 1024
	globCacheEvictDivisor = 4
	// escapedLen is the length of a backslash-escaped literal.
	escapedLen = 2
)

// globToken is one lexical element of an AppArmor path pattern.
type globToken int

const (
	// tokenLiteral is a literal character, possibly backslash-escaped.
	tokenLiteral globToken = iota
	// tokenStar is "*": any characters except "/".
	tokenStar
	// tokenDoubleStar is "**": any characters including "/".
	tokenDoubleStar
	// tokenQuestion is "?": a single character except "/".
	tokenQuestion
	// tokenClass is "[...]": a character class, optionally negated with
	// "^" or "!".
	tokenClass
	// tokenAlternation is "{a,b,...}": alternatives, which may nest and may
	// themselves contain glob tokens.
	tokenAlternation
)

// scanToken classifies the token starting at pos and returns the index just
// past it. Unbalanced "[" and "{" are literals.
func scanToken(pattern string, pos int) (int, globToken) {
	switch pattern[pos] {
	case '\\':
		return min(pos+escapedLen, len(pattern)), tokenLiteral
	case '*':
		if pos+1 < len(pattern) && pattern[pos+1] == '*' {
			return pos + len("**"), tokenDoubleStar
		}

		return pos + 1, tokenStar
	case '?':
		return pos + 1, tokenQuestion
	case '[':
		if end, ok := scanClass(pattern, pos); ok {
			return end, tokenClass
		}
	case '{':
		if end, ok := scanAlternation(pattern, pos); ok {
			return end, tokenAlternation
		}
	}

	return pos + 1, tokenLiteral
}

// scanClass finds the closing bracket of a character class starting at pos.
// A "]" directly after the opening bracket (or after a leading negation) is a
// member, not the terminator.
func scanClass(pattern string, pos int) (int, bool) {
	idx := pos + 1

	if idx < len(pattern) && (pattern[idx] == '^' || pattern[idx] == '!') {
		idx++
	}

	if idx < len(pattern) && pattern[idx] == ']' {
		idx++
	}

	for idx < len(pattern) {
		switch pattern[idx] {
		case '\\':
			idx += 2
		case ']':
			return idx + 1, true
		default:
			idx++
		}
	}

	return 0, false
}

// scanAlternation finds the closing brace matching the one at pos, honoring
// nested braces, character classes, and escapes.
func scanAlternation(pattern string, pos int) (int, bool) {
	depth := 0

	for idx := pos; idx < len(pattern); idx++ {
		switch pattern[idx] {
		case '\\':
			idx++
		case '[':
			idx = skipClass(pattern, idx)
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return idx + 1, true
			}
		}
	}

	return 0, false
}

// splitAlternatives splits the inside of an alternation at top-level commas,
// ignoring commas inside nested braces or character classes.
func splitAlternatives(inner string) []string {
	var (
		result []string
		depth  int
		start  int
	)

	for idx := 0; idx < len(inner); idx++ {
		switch inner[idx] {
		case '\\':
			idx++
		case '[':
			idx = skipClass(inner, idx)
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, inner[start:idx])
				start = idx + 1
			}
		}
	}

	return append(result, inner[start:])
}

// skipClass returns the index of the last byte of the character class
// starting at pos, or pos itself when the bracket is not a class.
func skipClass(pattern string, pos int) int {
	if end, ok := scanClass(pattern, pos); ok {
		return end - 1
	}

	return pos
}

// firstGlobToken returns the index of the first glob token in pattern, or
// -1 when the pattern is a plain literal.
func firstGlobToken(pattern string) int {
	for pos := 0; pos < len(pattern); {
		end, kind := scanToken(pattern, pos)
		if kind != tokenLiteral {
			return pos
		}

		pos = end
	}

	return -1
}

// IsGlobPattern reports whether the path contains AppArmor glob tokens:
// "*", "**", "?", character classes "[...]", or alternations "{a,b}".
// Backslash-escaped characters are literals.
func IsGlobPattern(path string) bool {
	return firstGlobToken(path) >= 0
}

func globToRegex(pattern string) *regexp.Regexp {
	globCacheMu.RLock()

	if cached, ok := globCacheEntries[pattern]; ok {
		globCacheMu.RUnlock()

		return cached
	}

	globCacheMu.RUnlock()

	compiled := compileGlob(pattern)

	globCacheMu.Lock()
	defer globCacheMu.Unlock()

	if cached, ok := globCacheEntries[pattern]; ok {
		return cached
	}

	if len(globCacheEntries) >= maxGlobCacheEntries {
		evictCount := maxGlobCacheEntries / globCacheEvictDivisor

		for key := range globCacheEntries {
			delete(globCacheEntries, key)

			evictCount--
			if evictCount == 0 {
				break
			}
		}
	}

	globCacheEntries[pattern] = compiled

	return compiled
}

// globNeverMatches reports whether a glob pattern exceeds the size limits
// and therefore matches nothing.
func globNeverMatches(pattern string) bool {
	return globToRegex(pattern) == neverMatchRe
}

func compileGlob(pattern string) *regexp.Regexp {
	if len(pattern) > maxGlobPatternLen {
		return neverMatchRe
	}

	budget := maxGlobAlternatives

	fragment, ok := globFragment(pattern, &budget, '/')
	if !ok {
		return neverMatchRe
	}

	compiled, err := regexp.Compile("^" + fragment + "$")
	if err != nil {
		return neverMatchRe
	}

	return compiled
}

// globFragment translates a pattern into an unanchored regex fragment. The
// budget bounds the total number of alternatives across nested groups. prev
// is the byte preceding the pattern in its enclosing context ('/' for a
// whole path, '{' or ',' inside an alternation) and decides whether a
// leading "*" or "**" starts a path component.
func globFragment(pattern string, budget *int, prev byte) (string, bool) {
	var builder strings.Builder

	for pos := 0; pos < len(pattern); {
		end, kind := scanToken(pattern, pos)

		before := prev
		if pos > 0 {
			before = pattern[pos-1]
		}

		fragment, ok := tokenFragment(pattern[pos:end], kind, budget, before == '/')
		if !ok {
			return "", false
		}

		builder.WriteString(fragment)

		pos = end
	}

	return builder.String(), true
}

// tokenFragment translates one token into a regex fragment. Only an
// alternation can fail, by exhausting the budget. As in the AppArmor parser,
// "*" and "**" at the start of a path component match at least one
// character, so "/dir/**" does not match "/dir/" itself.
func tokenFragment(
	token string, kind globToken, budget *int, componentStart bool,
) (string, bool) {
	switch kind {
	case tokenDoubleStar:
		if componentStart {
			return `[^/\000][^\000]*`, true
		}

		return `[^\000]*`, true
	case tokenStar:
		if componentStart {
			return `[^/\000][^/\000]*`, true
		}

		return `[^/\000]*`, true
	case tokenQuestion:
		return `[^/\000]`, true
	case tokenClass:
		return classFragment(token), true
	case tokenAlternation:
		return alternationFragment(token, budget)
	case tokenLiteral:
		return regexp.QuoteMeta(unescape(token)), true
	default:
		return regexp.QuoteMeta(token), true
	}
}

// alternationFragment translates a "{a,b,...}" token, compiling each
// alternative recursively.
func alternationFragment(token string, budget *int) (string, bool) {
	alternatives := splitAlternatives(token[1 : len(token)-1])

	*budget -= len(alternatives)
	if *budget < 0 {
		return "", false
	}

	var builder strings.Builder

	builder.WriteString("(?:")

	for idx, alternative := range alternatives {
		if idx > 0 {
			builder.WriteByte('|')
		}

		fragment, ok := globFragment(alternative, budget, '{')
		if !ok {
			return "", false
		}

		builder.WriteString(fragment)
	}

	builder.WriteByte(')')

	return builder.String(), true
}

// unescape strips the backslash from an escaped literal token.
func unescape(token string) string {
	if len(token) == escapedLen && token[0] == '\\' {
		return token[1:]
	}

	return token
}

// unescapeLiteral returns the file name denoted by a literal path, with
// backslash escapes resolved, for matching against glob regexes.
func unescapeLiteral(path string) string {
	if !strings.Contains(path, `\`) {
		return path
	}

	var builder strings.Builder

	for pos := 0; pos < len(path); pos++ {
		if path[pos] == '\\' && pos+1 < len(path) {
			pos++
		}

		builder.WriteByte(path[pos])
	}

	return builder.String()
}

// classFragment translates a "[...]" token into a regex character class.
// Ranges ("a-z") are kept; every other member is escaped.
func classFragment(token string) string {
	inner := token[1 : len(token)-1]

	var builder strings.Builder

	builder.WriteByte('[')

	if inner != "" && (inner[0] == '^' || inner[0] == '!') {
		builder.WriteByte('^')

		inner = inner[1:]
	}

	members := []rune(inner)

	for idx := 0; idx < len(members); idx++ {
		if members[idx] == '\\' && idx+1 < len(members) {
			idx++

			// Quote rather than re-escape: "\d" must stay a literal "d".
			builder.WriteString(regexp.QuoteMeta(string(members[idx])))

			continue
		}

		builder.WriteString(classMember(members, idx))
	}

	builder.WriteByte(']')

	return builder.String()
}

// classMember renders the class member at idx, keeping "-" as a range
// operator between two members and escaping regex metacharacters.
func classMember(members []rune, idx int) string {
	char := members[idx]

	if char == '-' && idx > 0 && idx+1 < len(members) {
		return "-"
	}

	if strings.ContainsRune(`\][^-`, char) {
		return `\` + string(char)
	}

	return string(char)
}

type apparmorPath struct {
	pattern string
	expr    *regexp.Regexp
}

type pathSet struct {
	globs    []apparmorPath
	literals map[string]struct{}
}

func newPathSet(patterns []string) pathSet {
	set := pathSet{
		globs:    make([]apparmorPath, 0, len(patterns)),
		literals: make(map[string]struct{}, len(patterns)),
	}

	seen := make(map[string]struct{}, len(patterns))

	for _, pat := range patterns {
		if _, ok := seen[pat]; ok {
			continue
		}

		seen[pat] = struct{}{}

		if IsGlobPattern(pat) {
			set.globs = append(set.globs, apparmorPath{
				pattern: pat, expr: globToRegex(pat),
			})
		} else {
			set.literals[pat] = struct{}{}
		}
	}

	return set
}

// matches reports whether a literal path is present or covered by a glob.
func (set *pathSet) matches(path string) bool {
	if _, ok := set.literals[path]; ok {
		return true
	}

	name := unescapeLiteral(path)

	for _, entry := range set.globs {
		if entry.expr.MatchString(name) {
			return true
		}
	}

	return false
}

// covers reports whether the set already grants everything the path grants:
// a literal is covered when present or matched by a glob, a glob only when
// present verbatim, since matching a pattern string against another glob's
// regex does not indicate language inclusion.
func (set *pathSet) covers(path string) bool {
	if IsGlobPattern(path) {
		return slices.ContainsFunc(set.globs, func(existing apparmorPath) bool {
			return existing.pattern == path
		})
	}

	return set.matches(path)
}

func (set *pathSet) add(pattern string) {
	if IsGlobPattern(pattern) {
		expr := globToRegex(pattern)

		// Remove exact duplicate glob.
		set.globs = slices.DeleteFunc(set.globs, func(existing apparmorPath) bool {
			return existing.pattern == pattern
		})

		// Prune literals subsumed by this glob. Glob-vs-glob
		// subsumption is not attempted because matching a glob
		// pattern string against another glob's regex does not
		// reliably indicate language inclusion.
		for lit := range set.literals {
			if expr.MatchString(unescapeLiteral(lit)) {
				delete(set.literals, lit)
			}
		}

		set.globs = append(set.globs, apparmorPath{
			pattern: pattern, expr: expr,
		})
	} else {
		set.literals[pattern] = struct{}{}
	}
}

func (set *pathSet) popExact(path string) bool {
	if _, ok := set.literals[path]; ok {
		delete(set.literals, path)

		return true
	}

	for idx, entry := range set.globs {
		if entry.pattern == path {
			set.globs = slices.Delete(set.globs, idx, idx+1)

			return true
		}
	}

	return false
}

func (set *pathSet) popCoveredLiterals(glob string) []string {
	expr := globToRegex(glob)

	var popped []string

	for lit := range set.literals {
		if expr.MatchString(unescapeLiteral(lit)) {
			popped = append(popped, lit)
		}
	}

	for _, lit := range popped {
		delete(set.literals, lit)
	}

	return popped
}

func (set *pathSet) patterns() []string {
	total := len(set.globs) + len(set.literals)
	if total == 0 {
		return nil
	}

	ret := make([]string, 0, total)

	for lit := range set.literals {
		ret = append(ret, lit)
	}

	for _, entry := range set.globs {
		ret = append(ret, entry.pattern)
	}

	return ret
}

// intersectPaths returns paths permitted by both sides, with glob awareness.
// Non-glob paths are kept when matched by a glob on the other side.
// For glob-vs-glob, prefix-based narrowing is attempted: if one glob's literal
// prefix contains the other's, the more specific pattern is kept. Otherwise,
// exact string match is used (conservative).
func intersectPaths(left, right []string) []string {
	leftSet := newPathSet(left)
	rightSet := newPathSet(right)

	seen := make(map[string]struct{})

	var result []string

	addPath := func(path string) {
		if _, ok := seen[path]; !ok {
			seen[path] = struct{}{}
			result = append(result, path)
		}
	}

	addMatchedLiterals(left, &rightSet, addPath)
	addMatchedLiterals(right, &leftSet, addPath)

	for _, leftPath := range left {
		if !IsGlobPattern(leftPath) || globNeverMatches(leftPath) {
			continue
		}

		for _, rightPath := range right {
			if !IsGlobPattern(rightPath) || globNeverMatches(rightPath) {
				continue
			}

			if narrowed := narrowGlobs(leftPath, rightPath); narrowed != "" {
				addPath(narrowed)
			}
		}
	}

	return result
}

func addMatchedLiterals(
	paths []string, matcher *pathSet, addPath func(string),
) {
	for _, path := range paths {
		if !IsGlobPattern(path) && matcher.matches(path) {
			addPath(path)
		}
	}
}

type fsPathEntry struct {
	path string
	perm fsPermission
	expr *regexp.Regexp
}

func buildFsEntries(perms map[string]fsPermission) []fsPathEntry {
	entries := make([]fsPathEntry, 0, len(perms))

	for path, perm := range perms {
		var expr *regexp.Regexp

		if IsGlobPattern(path) {
			expr = globToRegex(path)
			if expr == neverMatchRe {
				// An oversize pattern grants nothing, so it cannot
				// contribute to an intersection.
				continue
			}
		}

		entries = append(entries, fsPathEntry{
			path: path,
			perm: perm,
			expr: expr,
		})
	}

	return entries
}

// matchIntersectPaths returns the narrower path when one covers the other
// via glob matching, the path itself for exact matches, or empty string
// when the paths don't interact. For glob-vs-glob, prefix-based narrowing
// is used when possible, falling back to exact string match.
func matchIntersectPaths(left, right fsPathEntry) string {
	if left.path == right.path {
		return left.path
	}

	switch {
	case left.expr == nil && right.expr != nil:
		if right.expr.MatchString(unescapeLiteral(left.path)) {
			return left.path
		}
	case left.expr != nil && right.expr == nil:
		if left.expr.MatchString(unescapeLiteral(right.path)) {
			return right.path
		}
	case left.expr != nil && right.expr != nil:
		return narrowGlobs(left.path, right.path)
	}

	return ""
}

// globLiteralPrefix extracts the leading literal path segments before the
// first glob token. For example, "/var/log/**" returns "/var/log/",
// "/var/*/foo" returns "/var/", and "**" returns "".
func globLiteralPrefix(pattern string) string {
	first := firstGlobToken(pattern)
	if first < 0 {
		return pattern
	}

	prefix := pattern[:first]

	lastSlash := strings.LastIndex(prefix, "/")
	if lastSlash >= 0 {
		return prefix[:lastSlash+1]
	}

	return ""
}

// narrowGlobs returns the more specific glob when the other one is the
// "**" expansion of a literal prefix that contains the specific glob's
// prefix, so that "/etc/**" narrows to "/etc/*.conf" as well as to
// "/etc/foo/*.conf". Exact string matches are kept as-is. If neither glob
// contains the other in this way, returns empty string.
func narrowGlobs(left, right string) string {
	if left == right {
		return left
	}

	leftPrefix := globLiteralPrefix(left)
	rightPrefix := globLiteralPrefix(right)

	if left == leftPrefix+"**" && strings.HasPrefix(rightPrefix, leftPrefix) {
		return right
	}

	if right == rightPrefix+"**" && strings.HasPrefix(leftPrefix, rightPrefix) {
		return left
	}

	return ""
}
