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
	"regexp"
	"strings"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
	"sigs.k8s.io/security-profiles-merger/spm"
)

var (
	// ErrDuplicatePath is returned when a path appears in more than one
	// filesystem rule category of a profile, however each is spelled. Every
	// validator reports it, and so does a merge.
	ErrDuplicatePath = errors.New("duplicate path across filesystem categories")

	// ErrDuplicatePathInCategory is returned by the validators when a path
	// appears more than once within one filesystem rule category. The merge
	// folds such duplicates instead.
	ErrDuplicatePathInCategory = errors.New("duplicate path within category")

	// ErrDuplicateCapability is returned by the validators when a
	// capability appears more than once in AllowedCapabilities, compared
	// case-insensitively. The merge folds such duplicates instead.
	ErrDuplicateCapability = errors.New("duplicate capability")

	// ErrUnknownCapability is returned by ValidateStrict when a profile
	// contains a capability name not in the known set of Linux
	// capabilities.
	ErrUnknownCapability = errors.New("unknown capability")

	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = spm.ErrEmptyPath

	// ErrEmptyCapability is returned when a capability entry is an empty
	// string. Every validator reports it, and so does a merge.
	ErrEmptyCapability = errors.New("empty capability")

	// ErrDuplicateExecutablePath is returned by ValidateStrict when the
	// same path appears more than once in AllowedExecutables or
	// AllowedLibraries.
	ErrDuplicateExecutablePath = errors.New("duplicate executable path")

	// ErrGlobTooComplex is returned by ValidateStrict and ValidateArtifact
	// when a glob pattern exceeds the matcher's limits (100 alternatives in
	// total, or a compiled regex too large) and therefore never matches
	// anything: intersection would silently drop it.
	ErrGlobTooComplex = errors.New("glob pattern exceeds size or alternative limits")

	// ErrInvalidGlob is returned by ValidateStrict and ValidateArtifact when
	// a path is a pattern apparmor_parser rejects, such as an unclosed "{"
	// or "[", a "}" or "]" without its opening counterpart, an alternation
	// without a comma, alternations nested 50 deep, a malformed character
	// class, or a trailing backslash. It is also returned for the character
	// class forms the parser accepts but translates into something other
	// than what they say: "*" or "?" inside a class, an escaped "," inside a
	// class, and "[]" or "[^]". The merge functions treat such a pattern as
	// matching nothing.
	ErrInvalidGlob = errors.New("invalid AppArmor path pattern")

	// ErrPathTooLong is returned by every validator and by a merge when a
	// path is longer than MaxPathLen, the longest pattern the matcher
	// accepts and longer than any Linux path. The length is checked before
	// any other path check, so an oversized path costs no further work;
	// only the size limits of ValidateArtifact and ValidateStrict come
	// first.
	ErrPathTooLong = spm.ErrPathTooLong

	// ErrDotComponent is returned by ValidateStrict and ValidateArtifact
	// when a path has a literal "." or ".." component. The kernel hands
	// AppArmor canonical paths, so such a rule matches nothing; the merge
	// functions keep it as written rather than resolving it.
	ErrDotComponent = errors.New(`path contains a "." or ".." component`)

	// ErrUnsupportedVariable is returned when a path references an AppArmor
	// variable such as @{HOME}. Variables are expanded by the AppArmor
	// parser from definitions this package does not have, so it cannot tell
	// which files such a path covers and would match it as a literal "@"
	// followed by an alternation. The parser resolves escapes before it
	// expands variables, so `\x40{HOME}` is reported as well.
	ErrUnsupportedVariable = errors.New("AppArmor variables are not supported")

	// ErrRelativePath is returned by ValidateStrict and ValidateArtifact
	// when a path does not start with "/". AppArmor file rules must use
	// absolute paths.
	ErrRelativePath = spm.ErrRelativePath

	// ErrUnquotablePath is returned by ValidateStrict and ValidateArtifact
	// when a path holds a character apparmor_parser's lexer does not accept
	// unescaped in a file rule: a space, a tab, a carriage return, a
	// newline, a double quote, an exclamation mark, or a comma that does not
	// continue the path. Each has an escaped form the parser accepts and
	// this package resolves, so `/tmp/a\ b` names the file "/tmp/a b"
	// while "/tmp/a b" does not load at all. Beyond not loading, such a path
	// is how an artifact smuggles rules into a consumer that writes
	// its paths into a profile file: a newline ends the rule the consumer
	// renders and starts one the profile author chose. A backslash the
	// lexer does not read as an escape is reported too: one after a comma,
	// as in `/a,\ b`, where the space ends the path all the same, and one
	// that ends the path, which escapes the space rendered after it.
	ErrUnquotablePath = errors.New("path contains a character that must be escaped")

	// ErrNulInPath is returned by ValidateStrict and ValidateArtifact when a
	// path holds a NUL byte or an escape sequence denoting one, such as
	// "\000". apparmor_parser resolves the escape and loads the rule, but
	// the kernel never hands AppArmor a name holding a NUL, so the rule
	// matches nothing and vanishes from an intersection, like a path with a
	// "." component (ErrDotComponent) or a pattern past the matcher's limits
	// (ErrGlobTooComplex).
	ErrNulInPath = errors.New("path contains a NUL byte")

	// ErrInvalidCapabilityName is returned by ValidateArtifact and
	// ValidateStrict when a capability name holds a character that cannot
	// spell one. A capability is a word of letters, digits and "_", so a
	// name holding anything else does not load, and, like a path, is how an
	// artifact smuggles rules into a consumer that renders it.
	//
	// ValidateArtifact checks the spelling but not the name: a name this
	// package does not know may be one a newer kernel does. ValidateStrict
	// checks both, and reports an unknown name as ErrUnknownCapability.
	ErrInvalidCapabilityName = errors.New("invalid capability name")

	// ErrTooManyPaths is returned by ValidateArtifact and ValidateStrict
	// when a profile holds more than MaxArtifactPaths paths.
	ErrTooManyPaths = errors.New("too many paths")

	// ErrTooManyPatternBytes is returned by ValidateArtifact and
	// ValidateStrict when the glob patterns of a profile are longer than
	// MaxArtifactPatternBytes in total.
	ErrTooManyPatternBytes = errors.New("glob patterns too long in total")

	// ErrTooManyCapabilities is returned by ValidateArtifact and
	// ValidateStrict when a profile holds more than
	// MaxArtifactCapabilities capability names.
	ErrTooManyCapabilities = errors.New("too many capabilities")
)

// MaxPathLen is the longest path this package accepts, in bytes, which is
// also the longest pattern the matcher compiles. It is the limit the
// landlock package applies to its rule paths.
const MaxPathLen = spm.MaxPathLen

// MaxArtifactPaths bounds how many paths a profile accepted by
// ValidateArtifact or ValidateStrict may hold, counted over every path list
// of the profile. Profiles of the size KEP-6061 recommends runtimes accept
// name a few dozen.
//
// A merge matches the literal paths of one profile against the patterns of
// the other, which costs one comparison per pair, so the work grows with the
// product of the two counts rather than with their sum. Intersect and Union
// bound that work themselves and fall back to a conservative result past
// their budget, so no profile can hold a runtime in a merge; this cap
// rejects an over-large profile up front instead, where the reason can still
// be reported. It keeps an accepted profile inside the merge's pair budget
// when it is merged with another profile of this size, and inside its work
// budget, which weighs a comparison by the lengths of the pattern and the
// name, when its paths are a few dozen bytes long and it is merged with a
// baseline of a few kilobytes of paths.
const MaxArtifactPaths = 1024

// MaxArtifactPatternBytes bounds the total length of the glob patterns of a
// profile accepted by ValidateArtifact or ValidateStrict. Only paths holding
// pattern syntax count: a literal path is matched by comparison, while a
// pattern is compiled into a program first.
//
// A compiled pattern is cached, since the merge matches the same pattern
// against many names and validation reads it again. The cache is bounded,
// as anything holding data from a profile must be, so a profile whose
// patterns do not fit it is recompiled instead of reused: a profile of a
// thousand four-kilobyte patterns spent 38 seconds in ValidateArtifact and
// 14 in a merge against a four-rule baseline, none of it in matching. The
// byte bound admits two profiles of this size at once and leaves room for a
// baseline. The cache also holds at most 1024 patterns, as many as
// MaxArtifactPaths admits, so a profile a runtime accepts is compiled once
// unless it and the profiles merged with it spell more patterns than that
// together; past it a quarter of the cache is evicted, and an evicted
// pattern is compiled again when it is next used.
//
// Profiles of the size KEP-6061 recommends runtimes accept spell a few
// patterns of a few dozen bytes each.
const MaxArtifactPatternBytes = 64 << 10

// MaxArtifactCapabilities bounds how many capability names a profile
// accepted by ValidateArtifact or ValidateStrict may hold. A name need not
// be one this package knows, since a newer kernel may know it, so nothing
// else bounds the list: a profile naming a hundred thousand of them is
// merged in milliseconds but reported in megabytes, and every other section
// of an artifact is bounded. Linux has some forty capabilities.
const MaxArtifactCapabilities = 512

// asciiUpper upper-cases the ASCII letters of a name and leaves every other
// byte as it is. strings.ToUpper folds by Unicode rules, where U+017F and
// U+0131 upper-case into "S" and "I", so a capability spelled with one of
// them would compare equal to a real capability name, pass ValidateStrict as
// a known one, and be merged into the real one. A capability name is a word
// of ASCII characters (see ErrInvalidCapabilityName), so nothing a profile
// can spell needs the Unicode rules.
func asciiUpper(name string) string {
	var builder strings.Builder

	builder.Grow(len(name))

	for idx := range len(name) {
		char := name[idx]
		if char >= 'a' && char <= 'z' {
			char -= 'a' - 'A'
		}

		builder.WriteByte(char)
	}

	return builder.String()
}

func isKnownCapability(name string) bool {
	switch asciiUpper(name) {
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

// Validate checks an AppArmor profile for structural issues. It reports:
//
//   - paths longer than MaxPathLen (ErrPathTooLong), on their own and
//     before anything else;
//   - empty paths (ErrEmptyPath);
//   - paths referencing AppArmor variables, which the merge cannot
//     interpret (ErrUnsupportedVariable);
//   - a path listed in more than one filesystem category (ErrDuplicatePath)
//     or more than once within one (ErrDuplicatePathInCategory);
//   - empty capability names (ErrEmptyCapability) and capability names
//     listed more than once, compared case-insensitively
//     (ErrDuplicateCapability).
//
// Paths are compared as the merge matches them, with repeated slashes
// collapsed and escape sequences resolved, so "/etc//passwd",
// "/etc/passwd" and `/etc/\passwd` are one path. Nothing else is checked:
// patterns apparmor_parser rejects, duplicate executable and library paths
// and capability names outside the known set pass here and are reported by
// ValidateArtifact or ValidateStrict.
//
// Validate is what Intersect and Union run on each input after folding the
// duplicates within one list, so a merge fails on what Validate reports
// except a path or capability listed twice in one list. A profile listing
// one path twice is still worth reporting wherever a profile is checked
// rather than merged, since it says twice what it means once. See the
// Validation section of the package documentation.
//
// Failures are collected and returned together, up to 32: past that the
// error lists the first 32 and a count of the rest and matches
// ErrMoreProblems, so a sentinel a profile violates can be absent from the
// error that reports it.
func Validate(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	_, err := validateStructure(profile)

	return err
}

// validateStructure runs the checks of Validate on a non-nil profile and
// reports whether it stopped at an oversized path. ValidateStrict and
// ValidateArtifact read that flag rather than measuring every path again:
// their pattern checks have nothing to work on once a path is oversized.
func validateStructure(profile *Profile) (bool, error) {
	// Oversized paths are reported on their own: every other check scans
	// the paths.
	err := validatePathLengths(profile)
	if err != nil {
		return true, err
	}

	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, validateEmptyPaths(context, paths)...)
		errs = append(errs, validateNoVariables(context, paths)...)
	})

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
	}

	return false, merge.JoinLimited(errs...)
}

// ValidateStrict validates a profile a person wrote. It rejects everything
// ValidateArtifact rejects and, on top of that, capability names outside
// the known set of Linux capabilities (ErrUnknownCapability) and duplicate
// paths in AllowedExecutables or AllowedLibraries, compared as the merge
// matches them (ErrDuplicateExecutablePath). A profile that passes here
// therefore passes ValidateArtifact and Validate, the same order of
// strictness the seccomp and landlock packages use.
//
// It applies the limits ValidateArtifact applies (MaxArtifactPaths,
// MaxArtifactPatternBytes and MaxArtifactCapabilities), first and on their
// own: a profile that large is generated rather than written, and a
// generator is what the limits are there to keep in hand. The merge
// deduplicates executable and library paths and treats capability names as
// opaque, so Validate and ValidateArtifact accept both.
func ValidateStrict(profile *Profile) error {
	errs, err := artifactErrors(profile)
	if err != nil {
		return err
	}

	if profile.Capabilities != nil {
		errs = append(errs, validateCapabilityNames(profile.Capabilities.AllowedCapabilities))
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

	return merge.JoinLimited(errs...)
}

// ValidateArtifact validates an artifact: a profile the caller did not
// write, such as one a container runtime pulled from a registry. It runs
// every check of Validate and adds what a runtime could not load or would
// silently drop: relative paths (ErrRelativePath), patterns apparmor_parser
// rejects (ErrInvalidGlob), patterns past the matcher's limits
// (ErrGlobTooComplex), which would vanish from an intersection without a
// trace, "." or ".." components (ErrDotComponent) and NUL bytes
// (ErrNulInPath), which match nothing, characters apparmor_parser's lexer
// does not accept unescaped (ErrUnquotablePath), which a consumer rendering
// the profile would turn into rules of the author's choosing, and capability
// names that are not a word of letters, digits and "_"
// (ErrInvalidCapabilityName). See the Paths the validators reject section
// of the package documentation.
//
// A profile past MaxArtifactPaths (ErrTooManyPaths),
// MaxArtifactPatternBytes (ErrTooManyPatternBytes) or
// MaxArtifactCapabilities (ErrTooManyCapabilities) is refused first and on
// its own, rather than scanned.
//
// A capability name need not be one this package knows, since a newer
// kernel may know it, and duplicate executable and library paths are
// accepted, as the merge deduplicates them; ValidateStrict reports both.
// ValidateArtifact does not compare the profile against a baseline; callers
// intersect the result with their baseline afterwards.
func ValidateArtifact(profile *Profile) error {
	errs, err := artifactErrors(profile)
	if err != nil {
		return err
	}

	return merge.JoinLimited(errs...)
}

// artifactErrors runs the checks of ValidateArtifact and returns what they
// found. ValidateStrict starts from the same list and adds to it, so that a
// profile it accepts is one ValidateArtifact accepts by construction rather
// than by two functions being kept alike.
//
// The second result is a failure that ends validation on its own: a nil
// profile, or one past a size limit, which is refused rather than scanned.
func artifactErrors(profile *Profile) ([]error, error) {
	if profile == nil {
		return nil, ErrNilProfile
	}

	err := validatePathCount(profile)
	if err != nil {
		return nil, err
	}

	oversized, err := validateStructure(profile)

	var errs []error

	if err != nil {
		errs = append(errs, err)
	}

	if profile.Capabilities != nil {
		errs = append(errs, validateCapabilitySpelling(
			profile.Capabilities.AllowedCapabilities,
		)...)
	}

	if !oversized {
		errs = append(errs, validateLoadablePaths(profile)...)
	}

	return errs, nil
}

// validatePathCount reports a profile holding more paths than
// MaxArtifactPaths, or patterns longer in total than
// MaxArtifactPatternBytes, or more capabilities than MaxArtifactCapabilities.
// The message names the count and the limit it exceeds.
//
// Whether a path is a pattern is decided by the bytes it holds rather than
// by compiling it, so that counting an over-large profile costs no more than
// reading it.
func validatePathCount(profile *Profile) error {
	count := 0
	patternBytes := 0

	visitPathLists(profile, func(_ string, paths []string) {
		count += len(paths)

		for _, path := range paths {
			if strings.ContainsAny(path, patternSyntax) {
				patternBytes += len(path)
			}
		}
	})

	if count > MaxArtifactPaths {
		return fmt.Errorf("%d paths, at most %d: %w",
			count, MaxArtifactPaths, ErrTooManyPaths)
	}

	if patternBytes > MaxArtifactPatternBytes {
		return fmt.Errorf("%d bytes of glob patterns, at most %d: %w",
			patternBytes, MaxArtifactPatternBytes, ErrTooManyPatternBytes)
	}

	if profile.Capabilities != nil &&
		len(profile.Capabilities.AllowedCapabilities) > MaxArtifactCapabilities {
		return fmt.Errorf("%d capabilities, at most %d: %w",
			len(profile.Capabilities.AllowedCapabilities),
			MaxArtifactCapabilities, ErrTooManyCapabilities)
	}

	return nil
}

// validateLoadablePaths reports the paths apparmor_parser would refuse and
// the glob patterns the matcher drops, which ValidateStrict and
// ValidateArtifact both check. Callers run it only when no path is
// oversized, which validateStructure has already reported.
func validateLoadablePaths(profile *Profile) []error {
	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		// Normalizing never changes whether a path is absolute, which
		// characters it holds, or which escapes it spells beyond dropping
		// escaped slashes from a run of slashes, so those checks
		// read the raw paths and report them as written. The pattern checks
		// apply to the normalized form, which is what the merge matches.
		normalized := normalizePaths(paths)

		errs = append(errs, validateAbsolutePaths(context, paths)...)
		errs = append(errs, rejectPaths(
			context, paths, hasUnquotableChar, ErrUnquotablePath, true,
		)...)
		errs = append(errs, rejectPaths(
			context, paths, hasNul, ErrNulInPath, true,
		)...)
		errs = append(errs, validateGlobStatus(context, normalized)...)
		errs = append(errs, rejectPaths(
			context, normalized, hasDotComponent, ErrDotComponent, true,
		)...)
	})

	return errs
}

// validatePathLengths reports the paths longer than the pattern limit.
func validatePathLengths(profile *Profile) error {
	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, rejectPaths(context, paths, func(path string) bool {
			return len(path) > maxGlobPatternLen
		}, ErrPathTooLong, false)...)
	})

	return merge.JoinLimited(errs...)
}

// hasDotComponent reports whether a path has a "." or ".." component, with
// escape sequences resolved. For a glob, the components of the literal text
// before the first glob token count, and so do the later components that
// are exactly "." or ".." and lie outside every alternation and class: a
// dot component inside an alternation, as in "/{a,b/./c}", only rules out
// that alternative.
func hasDotComponent(path string) bool {
	matcher := matcherFor(path)

	switch matcher.kind {
	case kindInvalid:
		return false
	case kindLiteral:
		return dotComponent(matcher.literal)
	case kindGlob:
	}

	// The literal text ends inside the component holding the first glob
	// token, so only the components of its prefix are complete.
	return dotComponent(matcher.prefix) ||
		ungroupedDotComponent(filterSlashes(decodeEscapes(path)))
}

// ungroupedDotComponent reports whether a valid pattern, with escapes
// decoded and slashes filtered as convertPattern receives it, has a
// component outside every alternation and class that is exactly "." or
// "..". It scans as convertPattern does: a backslash makes the next
// character literal, "[" opens a class the next "]" closes, and "{" and "}"
// nest only outside a class. An escaped "/" still separates components, as
// the name holds a "/" there.
func ungroupedDotComponent(pattern string) bool {
	var scan dotScanner

	for idx := range len(pattern) {
		if scan.step(pattern[idx]) {
			return true
		}
	}

	return scan.endComponent()
}

// dotScanner holds the state of ungroupedDotComponent.
type dotScanner struct {
	component strings.Builder
	// grouped reports that the current component holds part of an
	// alternation or class.
	grouped bool
	inClass bool
	escaped bool
	depth   int
}

// step scans one character and reports whether it ends a dot component.
func (scan *dotScanner) step(char byte) bool {
	topLevel := scan.depth == 0 && !scan.inClass

	switch {
	case scan.escaped:
		scan.escaped = false
	case char == '\\':
		scan.escaped = true

		return false
	default:
		scan.nest(char)
	}

	switch {
	case !topLevel || scan.depth > 0 || scan.inClass:
		scan.grouped = true
	case char == '/':
		return scan.endComponent()
	default:
		scan.component.WriteByte(char)
	}

	return false
}

// nest tracks the classes and alternations an unescaped character opens or
// closes.
func (scan *dotScanner) nest(char byte) {
	switch {
	case char == '[':
		scan.inClass = true
	case char == ']':
		scan.inClass = false
	case scan.inClass:
	case char == '{':
		scan.depth++
	case char == '}':
		scan.depth--
	}
}

// endComponent ends the current component and reports whether it is an
// ungrouped "." or "..".
func (scan *dotScanner) endComponent() bool {
	text := scan.component.String()
	grouped := scan.grouped

	scan.component.Reset()
	scan.grouped = false

	return !grouped && (text == "." || text == "..")
}

// dotComponent reports whether a slash-separated text has a component that
// is exactly "." or "..".
func dotComponent(text string) bool {
	for component := range strings.SplitSeq(text, "/") {
		if component == "." || component == ".." {
			return true
		}
	}

	return false
}

// rejectPaths reports every path for which reject holds, quoting the path
// unless quote is false.
func rejectPaths(
	context string, paths []string, reject func(string) bool, sentinel error, quote bool,
) []error {
	var errs []error

	for idx, path := range paths {
		if !reject(path) {
			continue
		}

		if quote {
			errs = append(errs, fmt.Errorf(
				"%s[%d]: %s: %w", context, idx, merge.QuoteBounded(path), sentinel,
			))
		} else {
			errs = append(errs, fmt.Errorf("%s[%d]: %w", context, idx, sentinel))
		}
	}

	return errs
}

// validateNoVariables reports paths that reference an AppArmor variable. The
// parser resolves escapes before it expands variables, so `\x40{HOME}`
// references one as much as "@{HOME}" does: the check looks at the path with
// its escapes resolved too.
func validateNoVariables(context string, paths []string) []error {
	return rejectPaths(context, paths, func(path string) bool {
		return strings.Contains(path, "@{") ||
			strings.Contains(decodeEscapes(path), "@{")
	}, ErrUnsupportedVariable, true)
}

// validateAbsolutePaths reports paths that do not start with "/", the only
// form apparmor_parser accepts for a file rule. Empty paths are reported by
// Validate instead.
func validateAbsolutePaths(context string, paths []string) []error {
	return rejectPaths(context, paths, func(path string) bool {
		return path != "" && path[0] != '/'
	}, ErrRelativePath, true)
}

// unquotableChars are the characters apparmor_parser's lexer does not accept
// in an unquoted file rule: a path is a run of characters outside this set,
// with "\ ", "\t", `\"`, "\!" and "\," as the escaped forms it accepts
// instead. A comma is in the set because it ends the rule wherever the path
// does not go on, which hasUnquotableChar decides per occurrence.
const unquotableChars = " \t\r\n\"!,"

// lexerPath is the token apparmor_parser's lexer (parser_lex.l) reads as the
// path of a file rule, anchored so that it has to span the whole path:
//
//	ID_CHARS  [^ \t\r\n"!,]
//	ID        {ID_CHARS}|(,{ID_CHARS})|(\\[ ]|\\\t|\\\"|\\!|\\,)
//	LABEL     (\/|...){ID}*
//
// A backslash is an ID_CHARS character of its own, and a comma takes the
// character after it as a plain one, never as the start of an escape. The
// lexer takes the longest run of IDs, so where no split of the path into IDs
// exists, the token a consumer renders ends inside the path and the rest is
// read as profile syntax: in `/tmp/x,\ r,capability,/y` the comma takes the
// backslash, the space ends the token, and "r,capability,/y" follows it as
// rules. QUOTED_ID, the form a double quote opens, is never how a consumer
// renders a path and so does not apply.
var lexerPath = regexp.MustCompile(`^(?:[^ \t\r\n"!,]|,[^ \t\r\n"!,]|\\[ \t"!,])+$`)

// hasUnquotableChar reports whether a path holds a character of that set
// unescaped. A backslash makes the character after it part of the path,
// which is how a profile spells a path holding a space or a comma, and the
// merge resolves the escape the way the parser does. A comma is accepted
// where another path character follows it, as inside an alternation, and
// reported where the path ends or a character that cannot continue it
// follows, which is the "/foobar," the parser refuses.
//
// A backslash protects the character after it only where that character can
// be written in a rule at all. The parser resolves no escape whose second
// byte is a control character (see escapeSequence), so the backslash and the
// byte both survive into the rule: `/tmp/a\` followed by a raw newline is a
// path holding a newline, and a consumer rendering it writes a rule that
// ends mid-path and a second rule of the path author's choosing. The two-
// character forms spell the same paths safely (\n, \r, \t, or \x0a), so
// nothing is lost by refusing this one.
//
// Pairing each backslash with the next byte is how the merge reads a path,
// not how the lexer splits it, so the path also has to be one token to the
// lexer (see splitsLexerToken).
func hasUnquotableChar(path string) bool {
	if splitsLexerToken(path) {
		return true
	}

	for idx := 0; idx < len(path); idx++ {
		char := path[idx]

		switch {
		case char == '\\':
			idx++

			if idx < len(path) && isControlByte(path[idx]) {
				return true
			}
		case char == ',':
			if idx+1 >= len(path) || unquotable(path[idx+1]) {
				return true
			}
		case unquotable(char):
			return true
		}
	}

	return false
}

// splitsLexerToken reports whether apparmor_parser's lexer, reading the path
// as a consumer renders it in "  <path> <perms>,", would end the path's token
// anywhere but at its end: where the path is not a run of IDs (see
// lexerPath), or where it ends in a backslash, which the lexer reads as
// escaping the space after the path, so that even `/a\\` runs on into the
// permissions that follow it.
func splitsLexerToken(path string) bool {
	return strings.HasSuffix(path, `\`) || !lexerPath.MatchString(path)
}

// isControlByte reports whether a byte is one no rule can carry in the
// clear: the C0 controls and DEL. A path names them with an escape.
func isControlByte(char byte) bool {
	return char < 0x20 || char == 0x7f
}

// unquotable reports whether a character has to be escaped to stay part of a
// path.
func unquotable(char byte) bool {
	return strings.IndexByte(unquotableChars, char) >= 0
}

// hasNul reports whether a path holds a NUL byte or an escape sequence
// denoting one. The parser keeps such an escape as written where it resolves
// the others (see decodeEscapes) and resolves it when it compiles the rule,
// so the rule asks for a name holding a NUL, which no name the kernel hands
// AppArmor does. Scanning as decodeEscapes does keeps `\\000`, an escaped
// backslash followed by three digits, out of the report.
func hasNul(path string) bool {
	if strings.IndexByte(path, 0) >= 0 {
		return true
	}

	for pos := 0; pos < len(path); pos++ {
		if path[pos] != '\\' {
			continue
		}

		val, end, ok := escapeSequence(path, pos+1, "")
		if !ok {
			continue
		}

		if val == 0 {
			return true
		}

		pos = end - 1
	}

	return false
}

// validateCapabilitySpelling reports the capability names holding a
// character that cannot spell one. An empty name is left to
// validateEmptyCapabilities, which reports it as ErrEmptyCapability.
func validateCapabilitySpelling(caps []string) []error {
	var errs []error

	for idx, name := range caps {
		if name == "" || capabilityWord(name) {
			continue
		}

		errs = append(errs, fmt.Errorf(
			"AllowedCapabilities[%d]: %s: %w",
			idx, merge.QuoteBounded(name), ErrInvalidCapabilityName,
		))
	}

	return errs
}

// capabilityWord reports whether a name is spelled the way a capability is:
// letters, digits and "_", the characters apparmor_parser reads as one word.
func capabilityWord(name string) bool {
	for idx := range len(name) {
		char := name[idx]

		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '_':
		default:
			return false
		}
	}

	return true
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

// validateGlobStatus reports patterns apparmor_parser rejects and glob
// patterns that exceed the matcher's limits, both of which never match. It
// runs on normalized patterns, the form the merge matches, so it agrees with
// Intersect on what is dropped. A pattern over the limits is left out of the
// message, since it has over 100 alternatives.
func validateGlobStatus(context string, paths []string) []error {
	invalid := rejectPaths(context, paths, func(pattern string) bool {
		return matcherFor(pattern).status == globInvalid
	}, ErrInvalidGlob, true)

	tooComplex := rejectPaths(context, paths, func(pattern string) bool {
		return matcherFor(pattern).status == globTooComplex
	}, ErrGlobTooComplex, false)

	return append(invalid, tooComplex...)
}

func validateEmptyPaths(context string, paths []string) []error {
	return rejectPaths(context, paths, func(path string) bool {
		return path == ""
	}, ErrEmptyPath, false)
}

// validateEmptyPathsInProfile checks for empty and oversized paths before
// normalization, so that no normalization work is spent on an oversized
// path.
func validateEmptyPathsInProfile(profile *Profile) error {
	if profile == nil {
		return ErrNilProfile
	}

	err := validatePathLengths(profile)
	if err != nil {
		return err
	}

	var errs []error

	visitPathLists(profile, func(context string, paths []string) {
		errs = append(errs, validateEmptyPaths(context, paths)...)
	})

	return merge.JoinLimited(errs...)
}

// validateFilesystemPaths reports the paths listed in more than one
// category. Paths are compared by the rule they spell, not by their text, so
// that two spellings of one path are the pair of rules they are to
// apparmor_parser (see keyForPath).
func validateFilesystemPaths(rules *FilesystemRules) error {
	seen := make(map[pathKey]string)

	var errs []error

	for _, path := range rules.ReadOnlyPaths {
		seen[keyForPath(path)] = "ReadOnlyPaths"
	}

	for _, category := range []struct {
		name  string
		paths []string
	}{
		{"WriteOnlyPaths", rules.WriteOnlyPaths},
		{"ReadWritePaths", rules.ReadWritePaths},
	} {
		for _, path := range category.paths {
			key := keyForPath(path)

			if earlier, ok := seen[key]; ok {
				errs = append(errs, fmt.Errorf(
					"path %s in both %s and %s: %w",
					merge.QuoteBounded(path), earlier, category.name,
					ErrDuplicatePath,
				))
			}

			seen[key] = category.name
		}
	}

	return merge.JoinLimited(errs...)
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

	return merge.JoinLimited(errs...)
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

	return merge.JoinLimited(errs...)
}

func validateDuplicateCapabilities(caps []string) error {
	seen := make(map[string]struct{}, len(caps))

	var errs []error

	for _, cap := range caps {
		upper := asciiUpper(cap)
		if _, ok := seen[upper]; ok {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities: %s: %w",
				merge.QuoteBounded(cap), ErrDuplicateCapability,
			))
		}

		seen[upper] = struct{}{}
	}

	return merge.JoinLimited(errs...)
}

func validateCapabilityNames(caps []string) error {
	var errs []error

	for idx, cap := range caps {
		if cap != "" && !isKnownCapability(cap) {
			errs = append(errs, fmt.Errorf(
				"AllowedCapabilities[%d]: %s: %w",
				idx, merge.QuoteBounded(cap), ErrUnknownCapability,
			))
		}
	}

	return merge.JoinLimited(errs...)
}

// validateDuplicatesInSlice reports the paths of one list that spell a rule
// an earlier path of the list already spells (see keyForPath).
func validateDuplicatesInSlice(
	context string, items []string, sentinel error,
) []error {
	seen := make(map[pathKey]struct{}, len(items))

	var errs []error

	for _, item := range items {
		key := keyForPath(item)

		if _, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf(
				"%s: %s: %w", context, merge.QuoteBounded(item), sentinel,
			))
		}

		seen[key] = struct{}{}
	}

	return errs
}
