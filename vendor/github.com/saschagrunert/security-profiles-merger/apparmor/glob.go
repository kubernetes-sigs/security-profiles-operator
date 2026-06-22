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
)

var globTokenRe = regexp.MustCompile(`\*\*?|\?|\{[^}]+\}`)

// globToRegex converts an AppArmor glob pattern to a Go regular expression.
// Falls back to a never-matching regex on compilation failure, which cannot
// occur in practice because all literal segments are escaped and glob tokens
// map to fixed regex fragments.
var neverMatchRe = regexp.MustCompile(`^(?:$.)$`)

const (
	maxGlobPatternLen   = 4096
	maxGlobAlternatives = 100
)

func globToRegex(pattern string) *regexp.Regexp {
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

	re, err := regexp.Compile(builder.String())
	if err != nil {
		return neverMatchRe
	}

	return re
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
// (reverse). Returns the broader of the two patterns for promotion.
func (set *pathSet) popInteracting(path string) *string {
	for idx, entry := range set.paths {
		if entry.pattern == path {
			ret := entry.pattern

			set.removeAt(idx)

			return &ret
		}
	}

	for idx, entry := range set.paths {
		if entry.expr.MatchString(path) {
			ret := entry.pattern

			set.removeAt(idx)

			return &ret
		}
	}

	if globTokenRe.MatchString(path) {
		expr := globToRegex(path)
		found := false

		set.paths = slices.DeleteFunc(set.paths, func(existing apparmorPath) bool {
			matched := !globTokenRe.MatchString(existing.pattern) &&
				expr.MatchString(existing.pattern)
			if matched {
				delete(set.literals, existing.pattern)

				found = true
			}

			return matched
		})

		if found {
			ret := path

			return &ret
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
// Glob-vs-glob intersection uses exact string match only (conservative).
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

	for _, path := range left {
		if globTokenRe.MatchString(path) && slices.Contains(right, path) {
			addPath(path)
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
// when the paths don't interact. Glob-vs-glob uses exact string match only.
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
	}

	return ""
}
