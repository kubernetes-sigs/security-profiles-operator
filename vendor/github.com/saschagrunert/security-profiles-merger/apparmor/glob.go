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

	// globRegexCache caches compiled glob patterns for reuse.
	globRegexCache sync.Map //nolint:gochecknoglobals // process-wide cache
)

const (
	maxGlobPatternLen   = 4096
	maxGlobAlternatives = 100
)

func globToRegex(pattern string) *regexp.Regexp {
	if cached, ok := globRegexCache.Load(pattern); ok {
		compiled, _ := cached.(*regexp.Regexp)

		return compiled
	}

	compiled := compileGlob(pattern)
	actual, _ := globRegexCache.LoadOrStore(pattern, compiled)
	stored, _ := actual.(*regexp.Regexp)

	return stored
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

type apparmorPath struct {
	pattern string
	expr    *regexp.Regexp
}

type pathSet struct {
	paths    []apparmorPath
	literals map[string]struct{}
}

func newPathSet(patterns []string) pathSet {
	set := pathSet{paths: nil, literals: make(map[string]struct{})}

	for _, pat := range patterns {
		set.add(pat)
	}

	return set
}

// findMatch returns the index of the first entry whose regex matches path,
// or whose pattern equals path exactly. Only checks forward matching
// (existing pattern covers incoming path).
func (set *pathSet) findMatch(path string) int {
	if _, ok := set.literals[path]; ok {
		for idx, entry := range set.paths {
			if entry.pattern == path {
				return idx
			}
		}
	}

	for idx, entry := range set.paths {
		if entry.expr.MatchString(path) {
			return idx
		}
	}

	return -1
}

func (set *pathSet) matches(path string) bool {
	return set.findMatch(path) >= 0
}

func (set *pathSet) removeAt(idx int) {
	removed := set.paths[idx]
	if !globTokenRe.MatchString(removed.pattern) {
		delete(set.literals, removed.pattern)
	}

	set.paths = slices.Delete(set.paths, idx, idx+1)
}

// popInteracting removes all entries that interact with path.
// It checks both directions: existing patterns matching the incoming path
// (forward), and the incoming path matching existing non-glob entries
// (reverse). Returns all removed patterns so callers can promote each one.
func (set *pathSet) popInteracting(path string) []string {
	for idx, entry := range set.paths {
		if entry.pattern == path {
			set.removeAt(idx)

			return []string{entry.pattern}
		}
	}

	var matches []string

	set.paths = slices.DeleteFunc(set.paths, func(entry apparmorPath) bool {
		if entry.expr.MatchString(path) {
			delete(set.literals, entry.pattern)

			matches = append(matches, entry.pattern)

			return true
		}

		return false
	})

	if len(matches) > 0 {
		return matches
	}

	if globTokenRe.MatchString(path) {
		expr := globToRegex(path)

		set.paths = slices.DeleteFunc(set.paths, func(existing apparmorPath) bool {
			matched := !globTokenRe.MatchString(existing.pattern) &&
				expr.MatchString(existing.pattern)
			if matched {
				delete(set.literals, existing.pattern)

				matches = append(matches, existing.pattern)
			}

			return matched
		})

		if len(matches) > 0 {
			return append(matches, path)
		}
	}

	return nil
}

func (set *pathSet) add(pattern string) {
	expr := globToRegex(pattern)

	// Prune exact duplicates and non-glob entries subsumed by the new
	// pattern. Glob-vs-glob subsumption is not attempted because matching
	// a glob pattern string against another glob's regex does not reliably
	// indicate language inclusion.
	set.paths = slices.DeleteFunc(set.paths, func(existing apparmorPath) bool {
		if existing.pattern == pattern {
			return true
		}

		pruned := !globTokenRe.MatchString(existing.pattern) &&
			expr.MatchString(existing.pattern)
		if pruned {
			delete(set.literals, existing.pattern)
		}

		return pruned
	})

	set.paths = append(set.paths, apparmorPath{
		pattern: pattern,
		expr:    expr,
	})

	if !globTokenRe.MatchString(pattern) {
		set.literals[pattern] = struct{}{}
	}
}

func (set *pathSet) patterns() []string {
	if len(set.paths) == 0 {
		return nil
	}

	ret := make([]string, 0, len(set.paths))

	for _, entry := range set.paths {
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
		entries = append(entries, fsPathEntry{
			path: path,
			perm: perm,
			expr: globToRegex(path),
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

	leftIsGlob := globTokenRe.MatchString(left.path)
	rightIsGlob := globTokenRe.MatchString(right.path)

	switch {
	case !leftIsGlob && rightIsGlob:
		if right.expr.MatchString(left.path) {
			return left.path
		}
	case leftIsGlob && !rightIsGlob:
		if left.expr.MatchString(right.path) {
			return right.path
		}
	case leftIsGlob && rightIsGlob:
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
