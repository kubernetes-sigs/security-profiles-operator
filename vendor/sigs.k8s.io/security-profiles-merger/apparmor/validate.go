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
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

var (
	// ErrDuplicatePath is returned when a path appears in multiple
	// filesystem rule categories within the same profile.
	ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

	// ErrDuplicatePathInCategory is returned when a path appears more than
	// once within the same filesystem rule category.
	ErrDuplicatePathInCategory = errors.New("duplicate path within category")

	// ErrDuplicateCapability is returned when the same capability appears
	// more than once in AllowedCapabilities.
	ErrDuplicateCapability = errors.New("duplicate capability")

	// ErrUnknownCapability is returned when a profile contains a
	// capability name not in the known set of Linux capabilities.
	ErrUnknownCapability = errors.New("unknown capability")

	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = merge.ErrEmptyPath

	// ErrEmptyCapability is returned when a capability entry is an empty
	// string.
	ErrEmptyCapability = errors.New("empty capability")

	// ErrDuplicateExecutablePath is returned when the same path appears
	// more than once in AllowedExecutables or AllowedLibraries.
	ErrDuplicateExecutablePath = errors.New("duplicate executable path")

	// ErrGlobTooComplex is returned by ValidateStrict when a glob pattern
	// exceeds the matcher's limits (4096 bytes, or 100 alternatives in
	// total) and therefore never matches anything: intersection would
	// silently drop it.
	ErrGlobTooComplex = errors.New("glob pattern exceeds size or alternative limits")
)

func isKnownCapability(name string) bool {
	switch strings.ToUpper(name) {
	case "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
		"KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
		"NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW",
		"IPC_LOCK", "IPC_OWNER", "SYS_MODULE", "SYS_RAWIO",
		"SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT", "SYS_ADMIN",
		"SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
		"SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
		"AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN",
		"SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ",
		"PERFMON", "BPF", "CHECKPOINT_RESTORE":
		return true
	default:
		return false
	}
}

// Validate checks an AppArmor profile for structural issues.
// Capability names are validated against the known set of Linux
// capabilities. Filesystem paths and executable paths are not validated
// beyond being non-empty.
//
// The checks catch issues that would produce confusing merge results:
// duplicate paths across filesystem categories, which expand into
// ambiguous permission sets. Paths are compared in their normalized form,
// as the merge functions see them. All validation failures are collected
// and returned together.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateEmptyPathsInProfile(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile.Filesystem != nil {
		normalized := &FilesystemRules{
			ReadOnlyPaths:  normalizePaths(profile.Filesystem.ReadOnlyPaths),
			WriteOnlyPaths: normalizePaths(profile.Filesystem.WriteOnlyPaths),
			ReadWritePaths: normalizePaths(profile.Filesystem.ReadWritePaths),
		}

		err := validateFilesystemPaths(normalized)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicatePathsInCategory(normalized)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if profile.Capabilities != nil {
		err := validateEmptyCapabilities(
			profile.Capabilities.AllowedCapabilities,
		)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateDuplicateCapabilities(
			profile.Capabilities.AllowedCapabilities,
		)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateCapabilityNames(
			profile.Capabilities.AllowedCapabilities,
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally detects
// duplicate paths in AllowedExecutables and AllowedLibraries, compared in
// their normalized form, and glob patterns that exceed the matcher's limits
// and would never match. The merge path handles duplicates by
// deduplication and drops unmatchable globs on intersection, so Validate
// permits them. ValidateStrict is intended for user-authored profiles where
// both are likely mistakes.
func ValidateStrict(profile *Profile) error {
	var errs []error

	err := Validate(profile)
	if err != nil {
		errs = append(errs, err)
	}

	if profile == nil {
		return errors.Join(errs...)
	}

	if profile.Executable != nil {
		errs = append(errs, validateDuplicatesInSlice(
			"AllowedExecutables",
			normalizePaths(profile.Executable.AllowedExecutables),
			ErrDuplicateExecutablePath,
		)...)
		errs = append(errs, validateDuplicatesInSlice(
			"AllowedLibraries",
			normalizePaths(profile.Executable.AllowedLibraries),
			ErrDuplicateExecutablePath,
		)...)
	}

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, validateGlobLimits(context, normalizePaths(paths))...)
	})

	return errors.Join(errs...)
}

// visitPathLists calls visit for every list of paths in the profile, named
// after its field.
func visitPathLists(profile *Profile, visit func(context string, paths []string)) {
	if profile.Executable != nil {
		visit("AllowedExecutables", profile.Executable.AllowedExecutables)
		visit("AllowedLibraries", profile.Executable.AllowedLibraries)
	}

	if profile.Filesystem != nil {
		visit("ReadOnlyPaths", profile.Filesystem.ReadOnlyPaths)
		visit("WriteOnlyPaths", profile.Filesystem.WriteOnlyPaths)
		visit("ReadWritePaths", profile.Filesystem.ReadWritePaths)
	}
}

// validateGlobLimits reports glob patterns that exceed the matcher's limits
// and therefore never match. It runs on normalized patterns, the form the
// merge matches, so it agrees with Intersect on what is dropped. The pattern
// itself is left out of the message, since it is at least 4 KiB or has over
// 100 alternatives.
func validateGlobLimits(context string, paths []string) []error {
	var errs []error

	for idx, pattern := range paths {
		if IsGlobPattern(pattern) && globNeverMatches(pattern) {
			errs = append(errs, fmt.Errorf("%s[%d]: %w", context, idx, ErrGlobTooComplex))
		}
	}

	return errs
}

func validateEmptyPaths(context string, paths []string) []error {
	var errs []error

	for idx, path := range paths {
		if path == "" {
			errs = append(errs, fmt.Errorf(
				"%s[%d]: %w", context, idx, ErrEmptyPath,
			))
		}
	}

	return errs
}

// validateEmptyPathsInProfile checks for empty paths before normalization,
// since cleaning "" yields "." which would bypass Validate's check.
func validateEmptyPathsInProfile(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, validateEmptyPaths(context, paths)...)
	})

	return errors.Join(errs...)
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

func validateDuplicatePathsInCategory(rules *FilesystemRules) error {
	roErrs := validateDuplicatesInSlice(
		"ReadOnlyPaths", rules.ReadOnlyPaths, ErrDuplicatePathInCategory,
	)
	woErrs := validateDuplicatesInSlice(
		"WriteOnlyPaths", rules.WriteOnlyPaths, ErrDuplicatePathInCategory,
	)
	rwErrs := validateDuplicatesInSlice(
		"ReadWritePaths", rules.ReadWritePaths, ErrDuplicatePathInCategory,
	)

	errs := make([]error, 0, len(roErrs)+len(woErrs)+len(rwErrs))
	errs = append(errs, roErrs...)
	errs = append(errs, woErrs...)
	errs = append(errs, rwErrs...)

	return errors.Join(errs...)
}

func validateEmptyCapabilities(caps []string) error {
	var errs []error

	for idx, capability := range caps {
		if capability == "" {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities[%d]: %w", idx, ErrEmptyCapability,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateCapabilities(caps []string) error {
	seen := make(map[string]struct{}, len(caps))

	var errs []error

	for _, cap := range caps {
		upper := strings.ToUpper(cap)
		if _, ok := seen[upper]; ok {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities: %q: %w", cap, ErrDuplicateCapability,
			))
		}

		seen[upper] = struct{}{}
	}

	return errors.Join(errs...)
}

func validateCapabilityNames(caps []string) error {
	var errs []error

	for idx, cap := range caps {
		if cap != "" && !isKnownCapability(cap) {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities[%d]: %q: %w", idx, cap, ErrUnknownCapability,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicatesInSlice(
	context string, items []string, sentinel error,
) []error {
	seen := make(map[string]struct{}, len(items))

	var errs []error

	for _, item := range items {
		if _, ok := seen[item]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: %q: %w", context, item, sentinel,
			))
		}

		seen[item] = struct{}{}
	}

	return errs
}
