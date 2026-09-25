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
	addVariablePaths(&result, leftVariables, rightVariables)

	return result, nil
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
