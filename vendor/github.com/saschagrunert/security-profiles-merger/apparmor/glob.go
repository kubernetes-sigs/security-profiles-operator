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
	// globTokenRe matches AppArmor glob tokens: **, *, ?, and {alt1,alt2,...}.
	globTokenRe = regexp.MustCompile(`\*\*?|\?|\{[^}]+\}`)

	// neverMatchRe is a fallback regex that matches nothing.
	neverMatchRe = regexp.MustCompile(`^(?:$.)$`)

	// globCacheMu protects globCacheEntries.
	globCacheMu sync.RWMutex

	// globCacheEntries stores compiled glob regexes keyed by pattern.
	globCacheEntries = make(map[string]*regexp.Regexp)
)

const (
	maxGlobPatternLen   = 4096
	maxGlobAlternatives = 100
	maxGlobCacheEntries = 1024
)

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
		globCacheEntries = make(map[string]*regexp.Regexp)
	}

	globCacheEntries[pattern] = compiled

	return compiled
}

func compileGlob(pattern string) *regexp.Regexp {
	if len(pattern) > maxGlobPatternLen {
		return neverMatchRe
	}

	var builder strings.Builder

	builder.WriteString("^")

	lastEnd := 0

	for _, loc := range globTokenRe.FindAllStringIndex(pattern, -1) {
		builder.WriteString(regexp.QuoteMeta(pattern[lastEnd:loc[0]]))

		token := pattern[loc[0]:loc[1]]

		switch token {
		case "**":
			builder.WriteString(`[^\000]*`)
		case "*":
			builder.WriteString(`[^/\000]*`)
		case "?":
			builder.WriteString(`[^/\000]`)
		default:
			inner := token[1 : len(token)-1]
			alternatives := strings.Split(inner, ",")

			if len(alternatives) > maxGlobAlternatives {
				return neverMatchRe
			}

			for idx := range alternatives {
				alternatives[idx] = regexp.QuoteMeta(alternatives[idx])
			}

			builder.WriteString("(")
			builder.WriteString(strings.Join(alternatives, "|"))
			builder.WriteString(")")
		}

		lastEnd = loc[1]
	}

	builder.WriteString(regexp.QuoteMeta(pattern[lastEnd:]))
	builder.WriteString("$")

	compiled, err := regexp.Compile(builder.String())
	if err != nil {
		return neverMatchRe
	}

	return compiled
}

// IsGlobPattern reports whether the path contains AppArmor glob tokens.
func IsGlobPattern(path string) bool {
	return globTokenRe.MatchString(path)
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

		if globTokenRe.MatchString(pat) {
			set.globs = append(set.globs, apparmorPath{
				pattern: pat, expr: globToRegex(pat),
			})
		} else {
			set.literals[pat] = struct{}{}
		}
	}

	return set
}

func (set *pathSet) matches(path string) bool {
	if _, ok := set.literals[path]; ok {
		return true
	}

	for _, entry := range set.globs {
		if entry.expr.MatchString(path) {
			return true
		}
	}

	return false
}

func (set *pathSet) add(pattern string) {
	if globTokenRe.MatchString(pattern) {
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
			if expr.MatchString(lit) {
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
		if expr.MatchString(lit) {
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
		if !globTokenRe.MatchString(leftPath) {
			continue
		}

		for _, rightPath := range right {
			if !globTokenRe.MatchString(rightPath) {
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
		if !globTokenRe.MatchString(path) && matcher.matches(path) {
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
		if globTokenRe.MatchString(path) {
			expr = globToRegex(path)
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
		if right.expr.MatchString(left.path) {
			return left.path
		}
	case left.expr != nil && right.expr == nil:
		if left.expr.MatchString(right.path) {
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
	loc := globTokenRe.FindStringIndex(pattern)
	if loc == nil {
		return pattern
	}

	prefix := pattern[:loc[0]]

	lastSlash := strings.LastIndex(prefix, "/")
	if lastSlash >= 0 {
		return prefix[:lastSlash+1]
	}

	return ""
}

// narrowGlobs returns the more specific glob when one glob's literal prefix
// strictly contains the other's. Exact string matches are kept as-is.
// If neither prefix contains the other, returns empty string.
func narrowGlobs(left, right string) string {
	if left == right {
		return left
	}

	leftPrefix := globLiteralPrefix(left)
	rightPrefix := globLiteralPrefix(right)

	switch {
	case strings.HasPrefix(rightPrefix, leftPrefix) && leftPrefix != rightPrefix:
		if left == leftPrefix+"**" {
			return right
		}
	case strings.HasPrefix(leftPrefix, rightPrefix) && rightPrefix != leftPrefix:
		if right == rightPrefix+"**" {
			return left
		}
	}

	return ""
}
