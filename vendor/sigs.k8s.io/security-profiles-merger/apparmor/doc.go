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

// Package apparmor merges, compares and validates AppArmor profiles in the
// structured [Profile] form this package defines, which mirrors what the
// Security Profiles Operator records without depending on its CRD types.
//
// [Intersect] produces a profile that permits an operation only where every
// input permits it, which is what a CRI runtime needs to combine a profile
// pulled from an OCI artifact with its node baseline (KEP-6061). [Union]
// produces one that permits an operation where any input does, which is what
// the Security Profiles Operator needs to combine recorded profiles. Both
// document the merge semantics in full; [Diff] compares two profiles in the
// same terms.
//
// Paths are matched the way AppArmor matches them: this package ports the
// stages apparmor_parser runs a file rule through, so a glob pattern covers
// here what it covers on a node. [IsGlobPattern] reports whether a path is a
// pattern at all.
//
// # Validation
//
// [Validate] reports what makes a profile ill-formed: empty or oversized
// paths, paths this package cannot interpret, and paths or capabilities
// listed twice. [ValidateStrict] adds the checks worth making on a profile a
// person wrote, and [ValidateArtifact] the ones a runtime applies to a
// profile it did not author, including the patterns apparmor_parser rejects
// and the paths a consumer rendering the profile would turn into rules of the
// author's choosing.
//
// None of the three is a precondition of the merge, which is narrower than
// all of them: [Intersect] and [Union] fold duplicates together before they
// validate, drop the patterns that match nothing, and treat every other path
// as opaque text. They call [Validate] on each input, so what it reports
// fails a merge, but a profile it accepts is not thereby one the merge needs
// checked.
//
// # Scope
//
// [Profile] models the part of an AppArmor profile the Security Profiles
// Operator records: paths that may be executed or loaded as a library, paths
// that may be read, written or both, three network permissions, and
// capability names. It models nothing else, and this package neither reads
// nor writes profile text, so nothing is lost inside it; the loss is in
// whatever maps a real profile onto this type, and two of its consequences
// need stating.
//
// A file rule's exec transition modifiers (ix, px, Px, ux, Ux, cx, Cx, pix
// and the rest) have no place here, so two profiles listing one path in
// AllowedExecutables intersect to a shared exec permission even where one
// grants it "ix" and the other "Ux", which is not a permission they share.
// Callers must not map exec modes into AllowedExecutables where the
// distinction matters.
//
// A deny rule has no place here either, and a deny rule beats an allow rule
// in AppArmor whatever their order. A caller that maps only the allow rules
// of a profile holding deny rules produces a [Profile] granting more than
// the original, which every merge here then takes at face value. Callers
// must not map a profile holding deny rules onto this type.
//
// The other rule kinds a profile may hold are outside the model as well:
// the "m", "k", "l" and "a" permissions and link rules, owner conditionals,
// mount, umount and pivot_root rules, signal, ptrace, dbus and unix rules,
// abi and include directives, profile flags, and subprofiles or hats.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The package keeps one internal cache of analyzed glob patterns, guarded by
// its own lock, which is the only state shared between calls; it changes no
// result, only the work a repeated pattern costs. It does hold the pattern
// text of the profiles it analyzed, bounded by its own size limits and
// evicted as newer patterns arrive, so a process merging untrusted profiles
// keeps some of their paths in memory after a call returns. Concurrent calls
// only need their profiles not to be written to at the same time from
// elsewhere.
package apparmor
