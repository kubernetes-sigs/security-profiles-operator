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

// Package apparmor provides merge operations for AppArmor profiles.
package apparmor

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = merge.ErrNoProfiles
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = merge.ErrNilProfile
)

// Intersect merges multiple AppArmor profiles via intersection: the resulting
// profile permits an operation only if all input profiles permit it.
// Capabilities are intersected, file access rules are intersected, and network
// permissions use AND semantics.
//
// This implements the profile merging semantics defined in KEP-6061 for CRI
// runtimes merging OCI-pulled profiles with node baselines.
func Intersect(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, intersectStrategy{})
}

// Union merges multiple AppArmor profiles via union: the resulting profile
// permits an operation if any input profile permits it. Capabilities are
// combined, file access rules are combined, and network permissions use OR
// semantics.
//
// This implements the merge semantics used by the Security Profiles Operator
// for combining recorded profiles.
func Union(profiles ...*Profile) (*Profile, error) {
	return foldProfiles(profiles, unionStrategy{})
}

type strategy interface {
	mergeStrings(left, right []string) []string
	mergePaths(left, right []string) []string
	mergeBool(left, right *bool) *bool
	mergeFilesystem(left, right *FilesystemRules) *FilesystemRules
}

func foldProfiles(profiles []*Profile, mergeOp strategy) (*Profile, error) {
	for _, profile := range profiles {
		if profile == nil {
			return nil, fmt.Errorf("validate: %w", ErrNilProfile)
		}

		err := validateEmptyPathsInProfile(profile)
		if err != nil {
			return nil, fmt.Errorf("validate: %w", err)
		}
	}

	normalized := make([]*Profile, len(profiles))
	for idx, profile := range profiles {
		normalized[idx] = normalizeProfile(profile)
	}

	for _, profile := range normalized {
		err := Validate(profile)
		if err != nil {
			return nil, fmt.Errorf("validate: %w", err)
		}
	}

	result, err := merge.Fold(normalized, cloneProfile, func(a, b *Profile) *Profile {
		return mergeTwo(a, b, mergeOp)
	})
	if err != nil {
		return nil, fmt.Errorf("fold: %w", err)
	}

	sortProfile(result)

	return result, nil
}

func sortProfile(profile *Profile) {
	if profile.Executable != nil {
		slices.Sort(profile.Executable.AllowedExecutables)
		slices.Sort(profile.Executable.AllowedLibraries)
	}

	if profile.Filesystem != nil {
		slices.Sort(profile.Filesystem.ReadOnlyPaths)
		slices.Sort(profile.Filesystem.WriteOnlyPaths)
		slices.Sort(profile.Filesystem.ReadWritePaths)
	}

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

func mergeExecutable(left, right *ExecutableRules, mergeStrategy strategy) *ExecutableRules {
	if left == nil && right == nil {
		return nil
	}

	if left == nil {
		return cloneExecutable(right)
	}

	if right == nil {
		return cloneExecutable(left)
	}

	return &ExecutableRules{
		AllowedExecutables: mergeStrategy.mergePaths(
			left.AllowedExecutables,
			right.AllowedExecutables,
		),
		AllowedLibraries: mergeStrategy.mergePaths(
			left.AllowedLibraries,
			right.AllowedLibraries,
		),
	}
}

func mergeFilesystem(left, right *FilesystemRules, mergeStrategy strategy) *FilesystemRules {
	if left == nil && right == nil {
		return nil
	}

	if left == nil {
		return cloneFilesystem(right)
	}

	if right == nil {
		return cloneFilesystem(left)
	}

	return mergeStrategy.mergeFilesystem(left, right)
}

func mergeNetwork(left, right *NetworkRules, mergeStrategy strategy) *NetworkRules {
	if left == nil && right == nil {
		return nil
	}

	if left == nil {
		return cloneNetwork(right)
	}

	if right == nil {
		return cloneNetwork(left)
	}

	result := &NetworkRules{
		AllowRaw:  mergeStrategy.mergeBool(left.AllowRaw, right.AllowRaw),
		Protocols: nil,
	}

	switch {
	case left.Protocols != nil && right.Protocols != nil:
		result.Protocols = &AllowedProtocols{
			AllowTCP: mergeStrategy.mergeBool(left.Protocols.AllowTCP, right.Protocols.AllowTCP),
			AllowUDP: mergeStrategy.mergeBool(left.Protocols.AllowUDP, right.Protocols.AllowUDP),
		}
	case left.Protocols != nil:
		result.Protocols = cloneProtocols(left.Protocols)
	case right.Protocols != nil:
		result.Protocols = cloneProtocols(right.Protocols)
	}

	return result
}

func mergeCapabilities(left, right *CapabilityRules, mergeStrategy strategy) *CapabilityRules {
	if left == nil && right == nil {
		return nil
	}

	if left == nil {
		return cloneCapabilities(right)
	}

	if right == nil {
		return cloneCapabilities(left)
	}

	return &CapabilityRules{
		AllowedCapabilities: mergeStrategy.mergeStrings(
			left.AllowedCapabilities,
			right.AllowedCapabilities,
		),
	}
}

// intersectStrategy implements intersection (AND) semantics.
type intersectStrategy struct{}

func (intersectStrategy) mergeStrings(left, right []string) []string {
	return merge.IntersectSlice(left, right)
}

func (intersectStrategy) mergePaths(left, right []string) []string {
	return intersectPaths(left, right)
}

func (intersectStrategy) mergeBool(left, right *bool) *bool {
	if left == nil {
		return copyBool(right)
	}

	if right == nil {
		return copyBool(left)
	}

	val := *left && *right

	return &val
}

func (intersectStrategy) mergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	leftPerms := expandFsPerms(left)
	rightPerms := expandFsPerms(right)

	leftEntries := buildFsEntries(leftPerms)
	rightEntries := buildFsEntries(rightPerms)

	merged := make(map[string]fsPermission)

	for _, leftEntry := range leftEntries {
		for _, rightEntry := range rightEntries {
			key := matchIntersectPaths(leftEntry, rightEntry)
			if key == "" {
				continue
			}

			intersected := leftEntry.perm.intersect(rightEntry.perm)
			if !intersected.read && !intersected.write {
				continue
			}

			if existing, ok := merged[key]; ok {
				merged[key] = existing.union(intersected)
			} else {
				merged[key] = intersected
			}
		}
	}

	return collapseFsPerms(merged)
}

// unionStrategy implements union (OR) semantics.
type unionStrategy struct{}

func (unionStrategy) mergeStrings(left, right []string) []string {
	return merge.UnionSlice(left, right)
}

func (unionStrategy) mergePaths(left, right []string) []string {
	set := newPathSet(left)

	for _, path := range right {
		if globTokenRe.MatchString(path) || !set.matches(path) {
			set.add(path)
		}
	}

	return set.patterns()
}

func (unionStrategy) mergeBool(left, right *bool) *bool {
	if left == nil {
		return copyBool(right)
	}

	if right == nil {
		return copyBool(left)
	}

	val := *left || *right

	return &val
}

func (unionStrategy) mergeFilesystem(left, right *FilesystemRules) *FilesystemRules {
	readSet := newPathSet(left.ReadOnlyPaths)
	writeSet := newPathSet(left.WriteOnlyPaths)
	rwSet := newPathSet(left.ReadWritePaths)

	addReadWritePaths(right.ReadWritePaths, &readSet, &writeSet, &rwSet)
	addReadOnlyPaths(right.ReadOnlyPaths, &readSet, &writeSet, &rwSet)
	addWriteOnlyPaths(right.WriteOnlyPaths, &readSet, &writeSet, &rwSet)

	return &FilesystemRules{
		ReadOnlyPaths:  readSet.patterns(),
		WriteOnlyPaths: writeSet.patterns(),
		ReadWritePaths: rwSet.patterns(),
	}
}

func addReadWritePaths(
	additions []string,
	readSet, writeSet, rwSet *pathSet,
) {
	for _, path := range additions {
		if rwSet.matches(path) {
			continue
		}

		if pats := readSet.popInteracting(path); len(pats) > 0 {
			for _, pat := range pats {
				rwSet.add(pat)
			}
		} else if pats := writeSet.popInteracting(path); len(pats) > 0 {
			for _, pat := range pats {
				rwSet.add(pat)
			}
		} else {
			rwSet.add(path)
		}
	}
}

func addReadOnlyPaths(
	additions []string,
	readSet, writeSet, rwSet *pathSet,
) {
	for _, path := range additions {
		if rwSet.matches(path) || readSet.matches(path) {
			continue
		}

		if pats := writeSet.popInteracting(path); len(pats) > 0 {
			for _, pat := range pats {
				rwSet.add(pat)
			}
		} else {
			readSet.add(path)
		}
	}
}

func addWriteOnlyPaths(
	additions []string,
	readSet, writeSet, rwSet *pathSet,
) {
	for _, path := range additions {
		if rwSet.matches(path) {
			continue
		}

		if pats := readSet.popInteracting(path); len(pats) > 0 {
			for _, pat := range pats {
				rwSet.add(pat)
			}
		} else if !writeSet.matches(path) {
			writeSet.add(path)
		}
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

func copyBool(boolVal *bool) *bool {
	if boolVal == nil {
		return nil
	}

	val := *boolVal

	return &val
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
		AllowRaw:  copyBool(network.AllowRaw),
		Protocols: nil,
	}

	if network.Protocols != nil {
		clone.Protocols = cloneProtocols(network.Protocols)
	}

	return clone
}

func cloneProtocols(proto *AllowedProtocols) *AllowedProtocols {
	return &AllowedProtocols{
		AllowTCP: copyBool(proto.AllowTCP),
		AllowUDP: copyBool(proto.AllowUDP),
	}
}

func cloneCapabilities(caps *CapabilityRules) *CapabilityRules {
	return &CapabilityRules{
		AllowedCapabilities: slices.Clone(caps.AllowedCapabilities),
	}
}

func normalizeProfile(profile *Profile) *Profile {
	result := cloneProfile(profile)

	if result.Executable != nil {
		result.Executable.AllowedExecutables = normalizePaths(result.Executable.AllowedExecutables)
		result.Executable.AllowedLibraries = normalizePaths(result.Executable.AllowedLibraries)
	}

	if result.Filesystem != nil {
		result.Filesystem.ReadOnlyPaths = normalizePaths(result.Filesystem.ReadOnlyPaths)
		result.Filesystem.WriteOnlyPaths = normalizePaths(result.Filesystem.WriteOnlyPaths)
		result.Filesystem.ReadWritePaths = normalizePaths(result.Filesystem.ReadWritePaths)
	}

	return result
}

func normalizePaths(paths []string) []string {
	for idx, p := range paths {
		paths[idx] = filepath.Clean(p)
	}

	return paths
}
