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
	"errors"
	"fmt"
)

// ErrDuplicatePath is returned when a path appears in multiple
// filesystem rule categories within the same profile.
var ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

// Validate checks an AppArmor profile for structural issues.
// Capability names are not validated against a fixed set because the
// kernel may support capabilities unknown to this library. Filesystem
// paths and executable paths are also not validated.
//
// The checks catch issues that would produce confusing merge results:
// duplicate paths across filesystem categories, which expand into
// ambiguous permission sets. All validation failures are collected and
// returned together.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	if profile.Filesystem != nil {
		err := validateFilesystemPaths(profile.Filesystem)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateFilesystemPaths(rules *FilesystemRules) error {
	seen := make(map[string]string)

	var errs []error

	for _, path := range rules.ReadOnlyPaths {
		seen[path] = "ReadOnlyPaths"
	}

	for _, path := range rules.WriteOnlyPaths {
		if category, ok := seen[path]; ok {
			errs = append(errs, fmt.Errorf(
				"path %q in both %s and WriteOnlyPaths: %w",
				path, category, ErrDuplicatePath,
			))
		}

		seen[path] = "WriteOnlyPaths"
	}

	for _, path := range rules.ReadWritePaths {
		if category, ok := seen[path]; ok {
			errs = append(errs, fmt.Errorf(
				"path %q in both %s and ReadWritePaths: %w",
				path, category, ErrDuplicatePath,
			))
		}
	}

	return errors.Join(errs...)
}
