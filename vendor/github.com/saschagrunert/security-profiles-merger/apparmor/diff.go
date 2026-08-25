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
	"strings"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

// ProfileDiff describes the differences between two AppArmor profiles.
type ProfileDiff struct {
	// Equal is true when the two profiles are identical.
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

// IsEqual returns whether the two compared profiles are identical.
func (d ProfileDiff) IsEqual() bool { return d.Equal }

// StringSliceDiff represents added and removed items in a string slice.
type StringSliceDiff = merge.SliceDiff[string]

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

// BoolPtrDiff represents a change in an optional boolean value.
type BoolPtrDiff struct {
	Left  *bool `json:"left"`
	Right *bool `json:"right"`
}

// Diff compares two AppArmor profiles and returns a structured diff.
// Unlike Intersect and Union, Diff does not validate profiles before comparing.
// Paths are normalized and deduplicated before comparison to avoid false
// positives from non-canonical representations (e.g. /foo/./bar vs /foo/bar).
// Returns ErrNilProfile if either profile is nil.
func Diff(left, right *Profile) (*ProfileDiff, error) {
	if left == nil || right == nil {
		return nil, ErrNilProfile
	}

	normLeft := normalizeProfile(left)
	deduplicateProfile(normLeft)

	normRight := normalizeProfile(right)
	deduplicateProfile(normRight)

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

func diffExecutables(diff *ProfileDiff, left, right *Profile) {
	if execDiff := diffStringSlice(executablePaths(left), executablePaths(right)); execDiff != nil {
		diff.Equal = false
		diff.Executables = execDiff
	}

	if libDiff := diffStringSlice(libraryPaths(left), libraryPaths(right)); libDiff != nil {
		diff.Equal = false
		diff.Libraries = libDiff
	}
}

func executablePaths(profile *Profile) []string {
	if profile.Executable == nil {
		return nil
	}

	return profile.Executable.AllowedExecutables
}

func libraryPaths(profile *Profile) []string {
	if profile.Executable == nil {
		return nil
	}

	return profile.Executable.AllowedLibraries
}

func diffFilesystem(diff *ProfileDiff, left, right *Profile) {
	roDiff := diffStringSlice(fsPaths(left, fsReadOnly), fsPaths(right, fsReadOnly))
	woDiff := diffStringSlice(fsPaths(left, fsWriteOnly), fsPaths(right, fsWriteOnly))
	rwDiff := diffStringSlice(fsPaths(left, fsReadWrite), fsPaths(right, fsReadWrite))

	if roDiff != nil || woDiff != nil || rwDiff != nil {
		diff.Equal = false
		diff.Filesystem = &FilesystemDiff{
			ReadOnly:  roDiff,
			WriteOnly: woDiff,
			ReadWrite: rwDiff,
		}
	}
}

type fsCategory int

const (
	fsReadOnly fsCategory = iota
	fsWriteOnly
	fsReadWrite
)

func fsPaths(profile *Profile, category fsCategory) []string {
	if profile.Filesystem == nil {
		return nil
	}

	switch category {
	case fsReadOnly:
		return profile.Filesystem.ReadOnlyPaths
	case fsWriteOnly:
		return profile.Filesystem.WriteOnlyPaths
	case fsReadWrite:
		return profile.Filesystem.ReadWritePaths
	default:
		return nil
	}
}

func diffNetwork(diff *ProfileDiff, left, right *Profile) {
	var networkDiff NetworkDiff

	changed := false

	rawGetter := func(net *NetworkRules) *bool { return net.AllowRaw }

	if rawDiff := diffBoolPtr(
		netBoolPtr(left, rawGetter), netBoolPtr(right, rawGetter),
	); rawDiff != nil {
		networkDiff.AllowRaw = rawDiff
		changed = true
	}

	tcpGetter := func(proto *AllowedProtocols) *bool { return proto.AllowTCP }

	if tcpDiff := diffBoolPtr(
		protoBoolPtr(left, tcpGetter), protoBoolPtr(right, tcpGetter),
	); tcpDiff != nil {
		networkDiff.AllowTCP = tcpDiff
		changed = true
	}

	udpGetter := func(proto *AllowedProtocols) *bool { return proto.AllowUDP }

	if udpDiff := diffBoolPtr(
		protoBoolPtr(left, udpGetter), protoBoolPtr(right, udpGetter),
	); udpDiff != nil {
		networkDiff.AllowUDP = udpDiff
		changed = true
	}

	if changed {
		diff.Equal = false
		diff.Network = &networkDiff
	}
}

func netBoolPtr(profile *Profile, getter func(*NetworkRules) *bool) *bool {
	if profile.Network == nil {
		return nil
	}

	return getter(profile.Network)
}

func protoBoolPtr(profile *Profile, getter func(*AllowedProtocols) *bool) *bool {
	if profile.Network == nil || profile.Network.Protocols == nil {
		return nil
	}

	return getter(profile.Network.Protocols)
}

func diffBoolPtr(left, right *bool) *BoolPtrDiff {
	if left == nil && right == nil {
		return nil
	}

	if left == nil || right == nil || *left != *right {
		return &BoolPtrDiff{
			Left:  merge.ClonePtr(left),
			Right: merge.ClonePtr(right),
		}
	}

	return nil
}

func diffCapabilities(diff *ProfileDiff, left, right *Profile) {
	var leftCaps, rightCaps []string

	if left.Capabilities != nil {
		leftCaps = left.Capabilities.AllowedCapabilities
	}

	if right.Capabilities != nil {
		rightCaps = right.Capabilities.AllowedCapabilities
	}

	if capDiff := diffStringSlice(leftCaps, rightCaps); capDiff != nil {
		diff.Equal = false
		diff.Capabilities = capDiff
	}
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
	return merge.FormatDiffItems(prefix, sliceDiff.Removed, sliceDiff.Added)
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
