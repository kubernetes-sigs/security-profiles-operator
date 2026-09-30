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

package util

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"k8s.io/utils/ptr"
	"sigs.k8s.io/security-profiles-merger/apparmor"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

// UnionAppArmor merges two AppArmor profiles, so that the result allows what
// either of them allows.
//
// The merger rejects paths referencing AppArmor variables, like the @{pid}
// the recorder writes for /proc paths, as it cannot tell which files they
// match. Those paths are merged here by their text instead: a path with a
// variable never equals one without, so the merger does not need to see them.
//
// The merger returns capabilities upper-cased, while the API only accepts them
// in lower case, so they are lower-cased again.
func UnionAppArmor(
	base, additions *apparmorprofileapi.AppArmorAbstract,
) (apparmorprofileapi.AppArmorAbstract, error) {
	left, leftVariables := splitVariablePaths(base)
	right, rightVariables := splitVariablePaths(additions)

	merged, err := apparmor.Union(abstractToMergerProfile(left), abstractToMergerProfile(right))
	if err != nil {
		return apparmorprofileapi.AppArmorAbstract{}, fmt.Errorf("union apparmor: %w", err)
	}

	result := mergerProfileToAbstract(merged)
	if result.Capability != nil {
		result.Capability.AllowedCapabilities = LowerCapabilities(
			result.Capability.AllowedCapabilities,
		)
	}

	addVariablePaths(&result, leftVariables, rightVariables)
	result.Ptrace = unionPtrace(base.Ptrace, additions.Ptrace)

	return result, nil
}

// LowerCapabilities returns the capabilities lower-cased, as the API accepts
// them, sorted and without duplicates.
func LowerCapabilities(capabilities []string) []string {
	if capabilities == nil {
		return nil
	}

	result := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		result = append(result, strings.ToLower(capability))
	}

	slices.Sort(result)

	return slices.Compact(result)
}

// unionPtrace merges the ptrace rules, which the merger does not know. Both
// are a single rule, so a union of rules for different peers applies to every
// peer, which allows what either of them allows.
func unionPtrace(
	leftRules, rightRules *apparmorprofileapi.AppArmorPtraceRules,
) *apparmorprofileapi.AppArmorPtraceRules {
	left := ptr.Deref(leftRules, apparmorprofileapi.AppArmorPtraceRules{})
	right := ptr.Deref(rightRules, apparmorprofileapi.AppArmorPtraceRules{})

	access := slices.Concat(left.AllowedAccess, right.AllowedAccess)
	if len(access) == 0 {
		return nil
	}

	slices.Sort(access)

	peer := left.Peer

	switch {
	case len(left.AllowedAccess) == 0:
		peer = right.Peer
	case len(right.AllowedAccess) == 0:
		// Only the left rule grants anything, so its peer applies.
	case left.Peer != right.Peer:
		peer = ""
	}

	return &apparmorprofileapi.AppArmorPtraceRules{
		AllowedAccess: slices.Compact(access),
		Peer:          peer,
	}
}

// fileAccess is the access a filesystem rule grants.
type fileAccess uint8

const (
	fileRead fileAccess = 1 << iota
	fileWrite
)

// variablePaths holds the paths of a profile which reference a variable.
type variablePaths struct {
	executables []string
	libraries   []string
	files       map[string]fileAccess
}

// hasVariable reports whether an AppArmor path references a variable.
func hasVariable(path string) bool {
	return strings.Contains(path, "@{")
}

// splitVariablePaths returns a copy of the profile without the paths
// referencing a variable, and those paths.
func splitVariablePaths(
	profile *apparmorprofileapi.AppArmorAbstract,
) (*apparmorprofileapi.AppArmorAbstract, *variablePaths) {
	rest := profile.DeepCopy()
	variables := &variablePaths{files: map[string]fileAccess{}}

	split := func(paths *[]string, access fileAccess, variable *[]string) {
		if *paths == nil {
			return
		}

		kept := make([]string, 0, len(*paths))

		for _, path := range *paths {
			switch {
			case !hasVariable(path):
				kept = append(kept, path)
			case variable != nil:
				*variable = append(*variable, path)
			default:
				variables.files[path] |= access
			}
		}

		*paths = kept
	}

	if rest.Executable != nil {
		split(&rest.Executable.AllowedExecutables, 0, &variables.executables)
		split(&rest.Executable.AllowedLibraries, 0, &variables.libraries)
	}

	if rest.Filesystem != nil {
		split(&rest.Filesystem.ReadOnlyPaths, fileRead, nil)
		split(&rest.Filesystem.WriteOnlyPaths, fileWrite, nil)
		split(&rest.Filesystem.ReadWritePaths, fileRead|fileWrite, nil)
	}

	return rest, variables
}

// addVariablePaths adds the union of the paths referencing a variable to the
// merged profile. A file granted read access by one profile and write access
// by the other ends up granted both.
func addVariablePaths(
	merged *apparmorprofileapi.AppArmorAbstract,
	left, right *variablePaths,
) {
	executables := slices.Concat(left.executables, right.executables)
	libraries := slices.Concat(left.libraries, right.libraries)

	if len(executables) > 0 || len(libraries) > 0 {
		if merged.Executable == nil {
			merged.Executable = &apparmorprofileapi.AppArmorExecutablesRules{}
		}

		merged.Executable.AllowedExecutables = sortedUnion(
			merged.Executable.AllowedExecutables, executables,
		)
		merged.Executable.AllowedLibraries = sortedUnion(
			merged.Executable.AllowedLibraries, libraries,
		)
	}

	files := maps.Clone(left.files)
	for path, access := range right.files {
		files[path] |= access
	}

	if len(files) == 0 {
		return
	}

	if merged.Filesystem == nil {
		merged.Filesystem = &apparmorprofileapi.AppArmorFsRules{}
	}

	fs := merged.Filesystem

	for path, access := range files {
		switch access {
		case fileRead:
			fs.ReadOnlyPaths = append(fs.ReadOnlyPaths, path)
		case fileWrite:
			fs.WriteOnlyPaths = append(fs.WriteOnlyPaths, path)
		default:
			fs.ReadWritePaths = append(fs.ReadWritePaths, path)
		}
	}

	slices.Sort(fs.ReadOnlyPaths)
	slices.Sort(fs.WriteOnlyPaths)
	slices.Sort(fs.ReadWritePaths)
}

// sortedUnion returns the paths of both lists, sorted and without duplicates.
func sortedUnion(paths, more []string) []string {
	if len(more) == 0 {
		return paths
	}

	result := slices.Concat(paths, more)
	slices.Sort(result)

	return slices.Compact(result)
}
