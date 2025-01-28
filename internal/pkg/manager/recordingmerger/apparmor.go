/*
Copyright 2022 The Kubernetes Authors.

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

package recordingmerger

import (
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
)

type mergeableAppArmorProfile struct {
	apparmorprofileapi.AppArmorProfile
}

func (sp *mergeableAppArmorProfile) getProfile() client.Object {
	return &sp.AppArmorProfile
}

// Merge two AppArmor profiles. The first profile may use glob patterns
// for paths, whereas the second profile is expected to contain raw paths only.
func (sp *mergeableAppArmorProfile) merge(other mergeableProfile) error {
	otherSP, ok := other.(*mergeableAppArmorProfile)
	if !ok {
		return fmt.Errorf("cannot merge AppArmorProfile with %T", other)
	}

	a1 := &sp.Spec.Abstract
	a2 := &otherSP.Spec.Abstract

	if a1.Executable != nil && a2.Executable != nil {
		a1.Executable.AllowedExecutables = mergePaths(
			a1.Executable.AllowedExecutables,
			a2.Executable.AllowedExecutables,
		)
		a1.Executable.AllowedLibraries = mergePaths(
			a1.Executable.AllowedLibraries,
			a2.Executable.AllowedLibraries,
		)
	} else if a2.Executable != nil {
		a1.Executable = a2.Executable
	}

	mergeFilesystem(a1, a2)

	if a1.Network != nil && a2.Network != nil {
		a1.Network.AllowRaw = mergeBools(a1.Network.AllowRaw, a2.Network.AllowRaw)

		if a1.Network.Protocols != nil && a2.Network.Protocols != nil {
			a1.Network.Protocols.AllowTCP = mergeBools(a1.Network.Protocols.AllowTCP, a2.Network.Protocols.AllowTCP)
			a1.Network.Protocols.AllowUDP = mergeBools(a1.Network.Protocols.AllowUDP, a2.Network.Protocols.AllowUDP)
		} else if a2.Network.Protocols != nil {
			a1.Network.Protocols = a2.Network.Protocols
		}
	} else if a2.Network != nil {
		a1.Network = a2.Network
	}

	if a1.Capability != nil && a2.Capability != nil {
		a1.Capability.AllowedCapabilities = *mergeDedupSortStrings(
			&a1.Capability.AllowedCapabilities,
			&a2.Capability.AllowedCapabilities,
		)
	} else if a2.Capability != nil {
		a1.Capability = a2.Capability
	}

	return nil
}

func mergePaths(a, b *[]string) *[]string {
	if a == nil {
		return b
	}

	if b == nil {
		return a
	}

	merged := newAppArmorPathSet(a)
	for _, path := range *b {
		if !merged.Matches(path) {
			merged.Add(path)
		}
	}

	return merged.Patterns()
}

func mergeFilesystem(base, additions *apparmorprofileapi.AppArmorAbstract) {
	//nolint:nestif  // refactoring this makes it worse
	if base.Filesystem != nil && additions.Filesystem != nil {
		r := newAppArmorPathSet(base.Filesystem.ReadOnlyPaths)
		w := newAppArmorPathSet(base.Filesystem.WriteOnlyPaths)
		rw := newAppArmorPathSet(base.Filesystem.ReadWritePaths)

		if additions.Filesystem.ReadWritePaths != nil {
			for _, p := range *additions.Filesystem.ReadWritePaths {
				if rw.Matches(p) {
					// no changes necessary
				} else if pat := r.PopMatching(p); pat != nil {
					rw.Add(*pat)
				} else if pat := w.PopMatching(p); pat != nil {
					rw.Add(*pat)
				} else {
					rw.Add(p)
				}
			}
		}

		if additions.Filesystem.ReadOnlyPaths != nil {
			for _, p := range *additions.Filesystem.ReadOnlyPaths {
				if rw.Matches(p) {
					// no changes necessary
				} else if r.Matches(p) {
					// no changes necessary
				} else if pat := w.PopMatching(p); pat != nil {
					rw.Add(*pat)
				} else {
					r.Add(p)
				}
			}
		}

		if additions.Filesystem.WriteOnlyPaths != nil {
			for _, p := range *additions.Filesystem.WriteOnlyPaths {
				if rw.Matches(p) {
					// no changes necessary
				} else if pat := r.PopMatching(p); pat != nil {
					rw.Add(*pat)
				} else if w.Matches(p) {
					// no changes necessary
				} else {
					w.Add(p)
				}
			}
		}

		base.Filesystem = &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths:  r.Patterns(),
			WriteOnlyPaths: w.Patterns(),
			ReadWritePaths: rw.Patterns(),
		}
	} else if additions.Filesystem != nil {
		base.Filesystem = additions.Filesystem
	}
}

func newAppArmorPathSet(patterns *[]string) appArmorPathSet {
	m := appArmorPathSet{}

	if patterns != nil {
		for _, p := range *patterns {
			m.Add(p)
		}
	}

	return m
}

type appArmorPathSet struct {
	paths []apparmorPath
}

type apparmorPath struct {
	pattern string
	expr    *regexp.Regexp
}

func (m *appArmorPathSet) findMatch(path string) int {
	for i, p := range m.paths {
		if p.pattern == path {
			return i
		}

		if p.expr != nil && p.expr.MatchString(path) {
			return i
		}
	}

	return -1
}

func (m *appArmorPathSet) Matches(path string) bool {
	return m.findMatch(path) >= 0
}

func (m *appArmorPathSet) PopMatching(path string) *string {
	i := m.findMatch(path)
	if i >= 0 {
		ret := m.paths[i].pattern
		m.paths[i] = m.paths[len(m.paths)-1]
		m.paths = m.paths[:len(m.paths)-1]

		return &ret
	}

	return nil
}

func (m *appArmorPathSet) Add(pattern string) {
	rex, err := appArmorGlobToRegex(pattern)
	if err != nil {
		log.Printf("Failed to parse AppArmor glob pattern '%s': %x\n", pattern, err)
	}

	m.paths = append(m.paths, apparmorPath{
		pattern: pattern,
		expr:    rex,
	})
}

func (m *appArmorPathSet) Patterns() *[]string {
	if len(m.paths) == 0 {
		return nil
	}

	ret := make([]string, 0, len(m.paths))
	for _, p := range m.paths {
		ret = append(ret, p.pattern)
	}

	sort.Strings(ret)

	return &ret
}

// Convert AppArmor globs (https://gitlab.com/apparmor/apparmor/-/wikis/QuickProfileLanguage#file-globbing)
// to regular expressions for evaluation. This method may be inaccurate and should not be
// used for security-sensitive use-cases, but it is good enough for common patterns.
func appArmorGlobToRegex(pattern string) (*regexp.Regexp, error) {
	expr := "^" + regexp.MustCompile(`\*\*?|\?|\{.+?\}|\.`).ReplaceAllStringFunc(
		pattern, func(match string) string {
			switch match {
			case "**":
				return `[^\000]*`
			case "*":
				return `[^/\000]*`
			case "?":
				return `[^/]`
			case ".":
				return `\.`
			default:
				inner := regexp.QuoteMeta(match[1 : len(match)-1])
				inner = strings.ReplaceAll(inner, ",", "|")

				return "(" + inner + ")"
			}
		},
	) + "$"

	return regexp.Compile(expr)
}

func mergeBools(a, b *bool) *bool {
	if a == nil {
		return b
	}

	if b == nil {
		return a
	}

	merged := (*a || *b)

	return &merged
}

func mergeDedupSortStrings(a, b *[]string) *[]string {
	if a == nil {
		return b
	}

	if b == nil {
		return a
	}

	merged := append(*a, *b...)
	sort.Strings(merged)
	merged = compact(merged)

	return &merged
}

// TODO: replace this with slices.Compact once all platform support Go 1.21.
func compact(s []string) []string {
	//nolint:all
	if len(s) < 2 {
		return s
	}

	i := 1

	for k := 1; k < len(s); k++ {
		if s[k] != s[k-1] {
			if i != k {
				s[i] = s[k]
			}

			i++
		}
	}

	return s[:i]
}
