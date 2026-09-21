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

// Package seccomp merges, compares and validates seccomp profiles in the
// [specs.LinuxSeccomp] form of the OCI runtime-spec.
//
// [Intersect] produces a profile that permits a syscall only where every
// input permits it, which is what a CRI runtime needs to combine a profile
// pulled from an OCI artifact with its node baseline (KEP-6061). [Union]
// produces one that permits a syscall where any input does, which is what
// the Security Profiles Operator needs to combine recorded profiles. Both
// document the merge semantics in full; [Diff] compares two profiles in the
// same terms.
//
// [Validate] checks what a runtime needs to load a profile at all, and both
// merge functions run it on every input. [ValidateStrict] adds the checks
// worth making on a profile a person wrote, and [ValidateArtifact] the ones
// a runtime applies to a profile it did not author.
// [UnmarshalStrict] decodes a profile and refuses what encoding/json accepts
// silently, which is where a profile from somewhere else should enter.
//
// # Evaluation model
//
// runc and crun load a profile through libseccomp, adding one rule per entry
// and syscall name. Before that, they skip entries whose action and errno
// equal the profile default, and runc adds an entry that repeats an argument
// index as one rule per condition. The rules of one syscall are what this
// package calls its clauses.
//
// libseccomp compiles the clauses of a syscall into a decision tree and runs
// it first-match. The order is not the profile order and does not depend on
// the actions: conditions are ordered by argument index (highest first), then
// by operator class (SCMP_CMP_EQ, SCMP_CMP_NE and SCMP_CMP_MASKED_EQ before
// SCMP_CMP_LT and SCMP_CMP_LE before SCMP_CMP_GT and SCMP_CMP_GE), then by
// value. Where clauses with different actions overlap, the action a call
// gets therefore follows from that order rather than from the profile.
// libseccomp also compiles some clause sets to programs that match none of
// the clauses (under {ERRNO; ALLOW a0 < 3 && a1 == 2; ALLOW a0 > 3} the call
// read(2, 5) is allowed), refuses some with EEXIST, and never returns from
// adding others. No simple model is exact for every clause set.
//
// This package therefore relies on the compiled program only where it is
// known to be exact. The clauses of one syscall form a safe shape when they
// are:
//
//   - (a) unconditional: libseccomp drops every conditional clause of a
//     syscall that has an unconditional one, whichever is added first, and
//     keeps the first of several unconditional clauses;
//   - (b) a single conditional clause;
//   - (c) several clauses with one SCMP_CMP_EQ condition each, all on the
//     same argument index, whose values differ even in their lower 32 bits,
//     with any results;
//   - (d) several clauses with one condition each and the same result, where
//     no argument index shared by several clauses carries a range
//     comparison (SCMP_CMP_LT, SCMP_CMP_LE, SCMP_CMP_GT, SCMP_CMP_GE)
//     against a value above 32 bits, which libseccomp miscompiles;
//   - (e) two clauses with one condition each on the same argument index and
//     value, whose operators are complements (SCMP_CMP_EQ and SCMP_CMP_NE,
//     SCMP_CMP_LT and SCMP_CMP_GE, SCMP_CMP_LE and SCMP_CMP_GT), with any
//     results.
//
// In a safe shape at most one result applies to any call, so the order does
// not matter: a call gets the result of the clause it matches, or the
// default when it matches none. The libseccomp tests of this package
// compile all pairs of single conditions and 20,000 sampled triples on
// argument indices 0 and 1, with the actions SCMP_ACT_ALLOW and
// SCMP_ACT_LOG, and check the clause sets classified as safe against the
// program libseccomp compiles. CI runs them against libseccomp 2.5.5 and
// 2.6.1, each built from its release tarball, and TestLibseccompVersion
// fails unless the library that answered is the one built.
//
// Any other clause set is treated conservatively. Whatever libseccomp does
// with it, the result of a call is the default or the action of one of the
// clauses, so a merge reads such a syscall as one unconditional clause with
// the most restrictive of those actions when intersecting and the least
// restrictive when uniting. Merge results only
// contain safe shapes, and collapse whatever else they would contain in the
// same way.
//
// The model covers the program libseccomp compiles for a 64-bit
// architecture. For a 32-bit architecture listed in a profile, libseccomp
// compares only the lower 32 bits of each value, which the model does not
// follow.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions hold no state between calls and never modify their
// arguments, so concurrent calls only need their profiles not to be written
// to at the same time from elsewhere.
package seccomp
