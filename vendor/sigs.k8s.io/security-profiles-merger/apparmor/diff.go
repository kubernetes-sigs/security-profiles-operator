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

// ProfileDiff describes the differences between two AppArmor profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are equivalent after
	// normalization: paths normalized, capability names upper-cased,
	// duplicates removed, and omitted sections compared as the empty
	// sections they stand for (see Diff).
	Equal bool `json:"equal"`

	// Executables is set when the allowed executables differ.
	Executables *StringSliceDiff `json:"executables,omitempty"`

	// Libraries is set when the allowed libraries differ.
	Libraries *StringSliceDiff `json:"libraries,omitempty"`

	// Filesystem is set when the filesystem rules differ.
	Filesystem *FilesystemDiff `json:"filesystem,omitempty"`

	// Network is set when the network rules differ.
	Network *NetworkDiff `json:"network,omitempty"`

	// Capabilities is set when the capabilities differ.
	Capabilities *StringSliceDiff `json:"capabilities,omitempty"`
}

// IsEqual reports whether the two compared profiles are equivalent after
// normalization, as Equal does.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// StringSliceDiff represents added and removed items in a string slice.
type StringSliceDiff = spm.SliceDiff[string]

// FilesystemDiff describes differences in filesystem rules.
type FilesystemDiff struct {
	ReadOnly  *StringSliceDiff `json:"readOnly,omitempty"`
	WriteOnly *StringSliceDiff `json:"writeOnly,omitempty"`
	ReadWrite *StringSliceDiff `json:"readWrite,omitempty"`
}

// NetworkDiff describes differences in network rules.
type NetworkDiff struct {
	AllowRaw *BoolPtrDiff `json:"allowRaw,omitempty"`
	AllowTCP *BoolPtrDiff `json:"allowTcp,omitempty"`
	AllowUDP *BoolPtrDiff `json:"allowUdp,omitempty"`
}

// BoolPtrDiff represents a change in an optional boolean value. Diff sets
// both sides, since it compares an unset boolean as false.
type BoolPtrDiff struct {
	Left  *bool `json:"left"`
	Right *bool `json:"right"`
}

// Diff compares two AppArmor profiles and returns a structured diff. Unlike
// Intersect and Union, Diff does not validate profiles before comparing.
//
// Profiles are compared by what AppArmor loads from them, so a profile and
// its merge result compare equal unless the merge changed what the profile
// permits. Paths are compared by the rule they spell, as apparmor_parser
// reads them: /foo//bar, /foo/bar and an escaped spelling of either are one
// rule (while /foo/./bar, which matches nothing, is another), and an omitted
// section or network boolean is compared as the explicit empty section or
// false that it denies the same as, which is how Intersect writes it. A
// profile that says nothing about raw sockets and one that forbids them are
// therefore equal, and Diff(p, Intersect(p)) is equal unless p has glob
// patterns that match nothing, which Intersect drops. It returns
// ErrNilProfile if either profile is nil.
func Diff(left, right *Profile) (*ProfileDiff, error) {
	if left == nil || right == nil {
		return nil, ErrNilProfile
	}

	normLeft := normalizeProfile(left)
	deduplicateProfile(normLeft)
	populateEmpty(normLeft)

	normRight := normalizeProfile(right)
	deduplicateProfile(normRight)
	populateEmpty(normRight)

	diff := &ProfileDiff{
		Equal:        true,
		Executables:  nil,
		Libraries:    nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	diffExecutables(diff, normLeft, normRight)
	diffFilesystem(diff, normLeft, normRight)
	diffNetwork(diff, normLeft, normRight)
	diffCapabilities(diff, normLeft, normRight)

	return diff, nil
}

// The comparisons below read sections and network booleans without checking
// for nil: Diff runs them on profiles populateEmpty has made explicit.

func diffExecutables(diff *ProfileDiff, left, right *Profile) {
	execDiff := diffPaths(
		left.Executable.AllowedExecutables, right.Executable.AllowedExecutables,
	)
	if execDiff != nil {
		diff.Equal = false
		diff.Executables = execDiff
	}

	libDiff := diffPaths(left.Executable.AllowedLibraries, right.Executable.AllowedLibraries)
	if libDiff != nil {
		diff.Equal = false
		diff.Libraries = libDiff
	}
}

func diffFilesystem(diff *ProfileDiff, left, right *Profile) {
	roDiff := diffPaths(left.Filesystem.ReadOnlyPaths, right.Filesystem.ReadOnlyPaths)
	woDiff := diffPaths(left.Filesystem.WriteOnlyPaths, right.Filesystem.WriteOnlyPaths)
	rwDiff := diffPaths(left.Filesystem.ReadWritePaths, right.Filesystem.ReadWritePaths)

	if roDiff != nil || woDiff != nil || rwDiff != nil {
		diff.Equal = false
		diff.Filesystem = &FilesystemDiff{
			ReadOnly:  roDiff,
			WriteOnly: woDiff,
			ReadWrite: rwDiff,
		}
	}
}

func diffNetwork(diff *ProfileDiff, left, right *Profile) {
	networkDiff := NetworkDiff{
		AllowRaw: diffBool(left.Network.AllowRaw, right.Network.AllowRaw),
		AllowTCP: diffBool(left.Network.Protocols.AllowTCP, right.Network.Protocols.AllowTCP),
		AllowUDP: diffBool(left.Network.Protocols.AllowUDP, right.Network.Protocols.AllowUDP),
	}

	if networkDiff.AllowRaw != nil || networkDiff.AllowTCP != nil || networkDiff.AllowUDP != nil {
		diff.Equal = false
		diff.Network = &networkDiff
	}
}

// diffBool compares two network booleans, which populateEmpty has set, and
// returns nil when they agree. The diff holds copies of the values.
func diffBool(left, right *bool) *BoolPtrDiff {
	if *left == *right {
		return nil
	}

	return &BoolPtrDiff{Left: merge.ClonePtr(left), Right: merge.ClonePtr(right)}
}

func diffCapabilities(diff *ProfileDiff, left, right *Profile) {
	capDiff := diffStringSlice(
		left.Capabilities.AllowedCapabilities, right.Capabilities.AllowedCapabilities,
	)
	if capDiff != nil {
		diff.Equal = false
		diff.Capabilities = capDiff
	}
}

// diffPaths compares two path lists by the rule each path spells rather than
// by its text, as Validate and the merge do: "/etc/passwd" and an escaped
// spelling of it are one rule, so a profile and its merge result, which
// keeps one spelling per rule, do not differ in it. A path only one side
// holds is reported in that side's spelling.
func diffPaths(left, right []string) *StringSliceDiff {
	leftKeys := pathsByRule(left)
	rightKeys := pathsByRule(right)

	var added, removed []string

	for key, path := range leftKeys {
		if _, both := rightKeys[key]; !both {
			removed = append(removed, path)
		}
	}

	for key, path := range rightKeys {
		if _, both := leftKeys[key]; !both {
			added = append(added, path)
		}
	}

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	slices.Sort(added)
	slices.Sort(removed)

	return &StringSliceDiff{Added: added, Removed: removed}
}

// pathsByRule maps the rule each path spells to the simplest spelling the
// list holds for it.
func pathsByRule(paths []string) map[string]string {
	rules := make(map[string]string, len(paths))

	for _, path := range paths {
		key := ruleText(path)
		if kept, ok := rules[key]; !ok || simplestSpelling(path, kept) < 0 {
			rules[key] = path
		}
	}

	return rules
}

// ruleText identifies the rule a path spells without compiling it. Diff
// validates nothing, so it must stay linear in what it is given: the name a
// literal denotes, or the expression the matcher would compile for a
// pattern, which two spellings of one pattern share and which is what
// Validate and the merge identify it by (see keyForPath). That expression
// spells a class by its members, so "[a-c]" and "[abc]" are one rule here as
// they are there. A path the port rejects, or one too long for it, is
// identified by its text.
func ruleText(path string) string {
	if !strings.ContainsAny(path, patternSyntax) {
		return "l:" + filterSlashes(path)
	}

	if len(path) > maxGlobPatternLen {
		return "t:" + path
	}

	conv := convertPattern(filterSlashes(decodeEscapes(path)))

	switch conv.kind {
	case kindLiteral:
		return "l:" + literalBytes(conv.regex[:conv.literalEnd])
	case kindGlob:
		fragment, ok := translateRegex(conv.regex)

		switch {
		case !ok:
		case path[0] != '/':
			// A relative pattern loads no rule, so it is none an absolute
			// pattern spells, whatever their expressions.
			return "r:" + fragment
		default:
			return "g:" + fragment
		}
	case kindInvalid:
	}

	return "t:" + path
}

func diffStringSlice(left, right []string) *StringSliceDiff {
	added, removed := merge.DiffSlice(left, right)
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	return &StringSliceDiff{Added: added, Removed: removed}
}

// FormatDiff returns a human-readable representation of an AppArmor profile diff.
func FormatDiff(diff *ProfileDiff) string {
	if diff == nil {
		return "Diff{<nil>}"
	}

	if diff.Equal {
		return "Diff{equal}"
	}

	var parts []string

	parts = appendExecDiffs(parts, diff)
	parts = appendFSDiffs(parts, diff)

	if diff.Network != nil {
		parts = append(parts, formatNetworkDiff(diff.Network))
	}

	if diff.Capabilities != nil {
		parts = append(parts, formatStringSliceDiff("caps", diff.Capabilities))
	}

	return fmt.Sprintf("Diff{%s}", strings.Join(parts, " "))
}

func appendExecDiffs(parts []string, diff *ProfileDiff) []string {
	if diff.Executables != nil {
		parts = append(parts, formatStringSliceDiff("exec", diff.Executables))
	}

	if diff.Libraries != nil {
		parts = append(parts, formatStringSliceDiff("lib", diff.Libraries))
	}

	return parts
}

func appendFSDiffs(parts []string, diff *ProfileDiff) []string {
	if diff.Filesystem == nil {
		return parts
	}

	if diff.Filesystem.ReadOnly != nil {
		parts = append(parts, formatStringSliceDiff("r", diff.Filesystem.ReadOnly))
	}

	if diff.Filesystem.WriteOnly != nil {
		parts = append(parts, formatStringSliceDiff("w", diff.Filesystem.WriteOnly))
	}

	if diff.Filesystem.ReadWrite != nil {
		parts = append(parts, formatStringSliceDiff("rw", diff.Filesystem.ReadWrite))
	}

	return parts
}

func formatStringSliceDiff(prefix string, sliceDiff *StringSliceDiff) string {
	return merge.FormatSliceDiff(prefix, *sliceDiff)
}

func formatNetworkDiff(networkDiff *NetworkDiff) string {
	var parts []string

	if networkDiff.AllowRaw != nil {
		parts = append(parts, fmt.Sprintf(
			"raw:%s->%s",
			formatBoolPtrShort(networkDiff.AllowRaw.Left),
			formatBoolPtrShort(networkDiff.AllowRaw.Right),
		))
	}

	if networkDiff.AllowTCP != nil {
		parts = append(parts, fmt.Sprintf(
			"tcp:%s->%s",
			formatBoolPtrShort(networkDiff.AllowTCP.Left),
			formatBoolPtrShort(networkDiff.AllowTCP.Right),
		))
	}

	if networkDiff.AllowUDP != nil {
		parts = append(parts, fmt.Sprintf(
			"udp:%s->%s",
			formatBoolPtrShort(networkDiff.AllowUDP.Left),
			formatBoolPtrShort(networkDiff.AllowUDP.Right),
		))
	}

	return "net:" + strings.Join(parts, ",")
}

func formatBoolPtrShort(boolPtr *bool) string {
	if boolPtr == nil {
		return "<nil>"
	}

	if *boolPtr {
		return "true"
	}

	return "false"
}
