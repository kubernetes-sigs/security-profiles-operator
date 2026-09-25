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
// input permits it, which is what a CRI runtime needs to combine an
// artifact (the untrusted profile it pulled) with its baseline (the profile
// it trusts), as KEP-6061 describes. [Union] produces one that permits an
// operation where any input does, which is what the Security Profiles
// Operator needs to combine recorded profiles. [Diff] compares two profiles
// in the same terms.
//
// Paths are matched the way AppArmor matches them: this package ports the
// stages apparmor_parser runs a file rule through, so a glob pattern covers
// here what it covers on a node. [IsGlobPattern] reports whether a path is a
// pattern at all.
//
// [UnmarshalStrict] decodes a profile and refuses what encoding/json accepts
// silently: members no field reads, members that name a field only ignoring
// case, members repeated within one object, invalid UTF-8 and data behind
// the profile. Decode an artifact with it and validate the result with
// [ValidateArtifact].
//
// # Validation
//
// [Validate] reports what makes a profile ill-formed: empty or oversized
// paths, AppArmor variables, and paths or capabilities listed twice.
// [ValidateArtifact] adds the checks a runtime applies to an artifact: the
// size limits, the patterns apparmor_parser rejects, and the paths a
// consumer rendering the profile would turn into rules of the author's
// choosing. [ValidateStrict] adds the checks worth making on a profile a
// person wrote, so each rejects everything the one before it rejects.
//
// Validate is what the merge runs on its inputs, after folding the
// duplicates within one list. [Intersect] and [Union] first drop exact
// duplicates, upper-case capability names and fold two spellings of one path
// within a list into one entry, then run Validate on each input. A merge
// therefore fails on a nil profile, an empty or oversized path, an AppArmor
// variable, a path listed in two filesystem categories (ErrDuplicatePath,
// however either is spelled) and an empty capability name, but not on a
// path or capability listed twice within one list. Everything else, such as
// a pattern apparmor_parser rejects, the merge treats as opaque text or as a
// pattern matching nothing. A failure is wrapped in an [InputError] naming
// the input.
//
// Every validator collects its failures and returns them together, up to
// 32 of them: past that the error lists the first 32 and a count of the
// rest, and matches [ErrMoreProblems], so a sentinel a profile violates can
// be absent from the error that reports it. An oversized path ends the path
// checks of Validate and the pattern checks of ValidateArtifact and
// ValidateStrict, since each would scan it, and ValidateArtifact and
// ValidateStrict check the size limits first and on their own.
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
// # Capability names
//
// Capability names are compared with ASCII case folding, and the merge
// upper-cases the names it keeps, so a result spells "CHOWN" rather than
// "chown". The folding is deliberately not Unicode's: U+017F and U+0131
// upper-case into "S" and "I", which would let a name spelled with one of
// them pass ValidateStrict as a known capability and merge into the real
// one. apparmor_parser accepts capability names in lower case only, so a
// consumer rendering a result as "capability <name>," rules must lower-case
// each name first; written as the merge returns them, the rules do not load.
//
// Otherwise the merge treats a name as opaque: an intersection keeps one
// only when every profile grants it, and a union keeps every name any
// profile grants. Validate accepts any non-empty name, because the kernel
// gains capabilities over time and failing a merge because one input names
// a capability newer than this package would leave callers unable to merge
// at all. ValidateArtifact requires a word of letters, digits and "_"
// ([ErrInvalidCapabilityName]), for the reason it reports an unquotable
// path, but does not check the name against the known set, since a newer
// kernel may know it. ValidateStrict also reports a name outside the known
// set ([ErrUnknownCapability]), which in a profile a person wrote is a typo.
//
// # Glob patterns
//
// Paths may use AppArmor glob syntax: "*" (any bytes except "/"), "**" (any
// bytes including "/"), "?" (one byte except "/"), character classes such
// as "[abc]", "[a-z]" and "[^a]", and alternations such as "{a,b}", which
// may nest and may contain further glob tokens. The results of a merge are
// loaded by apparmor_parser, so the package gives every pattern the meaning
// the parser gives it, in both directions: it ports the parser's escape
// handling, slash filtering, and translation of patterns into its
// byte-oriented regex engine (convert_aaregex_to_pcre and libapparmor_re).
// In particular:
//
//   - Matching works on bytes, not characters: "?" matches one byte, so
//     "/tmp/?" does not match "/tmp/é" (two bytes in UTF-8) and "/tmp/??"
//     does, and a class member such as "é" stands for each of its bytes.
//   - A run of two or more stars is one "**": the extra stars match what the
//     first two already match, so "/etc/***" narrows another pattern exactly
//     as "/etc/**" does rather than dropping out of an intersection.
//   - A star run requires a character only when it fills a whole path
//     component: when it follows a "/" and is followed by "/" or ends the
//     pattern. So "/dir/*" and "/dir/**" do not match "/dir/" itself, while
//     "/etc/*.conf" matches "/etc/.conf" and "/etc/**foo" matches
//     "/etc/foo". The parser checks the last character it emitted and the
//     raw pattern character after the run, so inside an alternation
//     "/etc/{x/*,y}" matches "/etc/x/" (the run follows "/" but is followed
//     by ","), and "/etc/{a,*}" matches "/etc/" (the run follows the
//     alternation's separator, not "/").
//   - Classes are passed to the regex engine as written: only "^" negates
//     ("[!a]" matches "!" and "a", and is reported as [ErrUnquotablePath]
//     for the unescaped "!"), a class may match "/" ("[/]", "[^a]", or a
//     range spanning it), "-" between two members is a range operator even
//     when escaped, and a reversed range such as "[z-a]" is swapped.
//
// A pattern with more than 100 alternatives in total never matches, and
// neither does a pattern apparmor_parser rejects (see Paths the validators
// reject). The merge drops such a pattern on intersection and keeps it
// verbatim on union. Intersecting a single profile drops them too, so
// Intersect(p) equals Intersect(p, p).
//
// # Path spelling
//
// Escape sequences are resolved as the parser resolves them: \n, \t, \r, \f,
// \a, \e, octal (\101), decimal (\d65) and hex (\x41) denote the byte they
// encode, so `/tmp/\x41` names "/tmp/A", while a sequence that encodes a
// pattern metacharacter (\x2a) stays a literal "*". A backslash before any
// other character makes it literal (`\*`, `\{`) or, for an ordinary
// character, is dropped (`\q` is "q"). An escaped literal such as `/etc/\*`
// is matched against globs as the file name "/etc/*".
//
// Paths are normalized as the parser's filter_slashes normalizes them: a
// path starting with exactly two slashes keeps them ("//a//b" becomes
// "//a/b"), and every other run of slashes collapses into one ("///a"
// becomes "/a"). As in the parser, an escape that encodes a slash (\x2f,
// \057, \d047) counts as one, so `///\x2fetc` becomes "/etc". A trailing
// slash is kept, which distinguishes a directory rule from a file rule. "."
// and ".." components are not resolved: the kernel hands AppArmor canonical
// paths, so a rule such as "/etc/../etc/passwd" matches nothing, and
// resolving it would make it grant "/etc/passwd". The merge keeps such paths
// as written.
//
// Two spellings of one path are one rule. The validators compare paths with
// repeated slashes collapsed and escapes resolved, so "/tmp/A" and
// `/tmp/\x41` listed in two categories are reported with [ErrDuplicatePath],
// and the merge folds two spellings within one list into one entry. Two
// profiles spelling one rule differently are given a common spelling before
// they are merged, so intersecting a profile listing "/tmp/A" with one
// listing `/tmp/\x41` keeps the file both grant. The spelling kept is one an
// input holds once its slash runs are filtered, never one derived from the
// decoded name, and among them one that stays renderable as a rule, then the
// shortest: deriving it could produce a path ValidateArtifact rejects
// ([ErrUnquotablePath]) from inputs it accepts.
//
// # Paths the validators reject
//
// Validate reports a path longer than [MaxPathLen] ([ErrPathTooLong]), an
// empty path ([ErrEmptyPath]) and an AppArmor variable such as @{HOME}
// ([ErrUnsupportedVariable]), whose expansion this package does not know.
// The variable check applies also where the "@" is spelled as an escape
// (`\x40{HOME}`), since the parser resolves escapes before it expands
// variables. Validate accepts everything below, and the merge treats it as
// opaque text or as a pattern matching nothing; ValidateArtifact and
// ValidateStrict report it.
//
// A pattern apparmor_parser rejects is reported with [ErrInvalidGlob]: an
// unclosed "{" or "[", a "}" or "]" without its opening counterpart (in
// "[]a]" the first "]" closes the class), an alternation without a comma
// ("{a}", "{*}", "{}"), alternations nested 50 deep, a malformed class such
// as "[a-]", a trailing backslash, and a NUL byte. So are the class forms
// the parser accepts but translates into something other than what they
// say: "*" or "?" inside a class, an escaped "," inside a class, and "[]" or
// "[^]". IsGlobPattern reports such paths as patterns. A pattern past the
// matcher's limits is reported with [ErrGlobTooComplex].
//
// A path is written the way apparmor_parser's lexer reads one: a run of
// characters other than space, tab, carriage return, newline, `"`, "!" and
// ",", which each have an escaped form (`\ `, \t, `\"`, `\!`, `\,`) the
// parser accepts and this package resolves. A comma is also accepted where
// another path character follows it, as inside an alternation "{a,b}". A
// path holding one of these unescaped is reported with [ErrUnquotablePath]:
// the rule does not load, and a consumer that renders "  <path> <perms>,\n"
// would turn a path holding a newline into further rules of the profile
// author's choosing. A backslash protects only a character that can be
// written in a rule: the parser resolves no escape whose second byte is a
// control character, so a backslash followed by a raw newline leaves both
// bytes in the path and is reported too. The two-character forms (\n, \r,
// \t, or \x0a) spell those paths safely. A backslash also escapes only where
// the lexer reads it as the start of an escape: after a comma the lexer
// takes the next byte as a plain character, so in `/a,\ b` the space still
// ends the path and the rest is read as profile syntax, and a path ending in
// a backslash (including an escaped one, `/a\\`) escapes the space a
// consumer renders after it. Both are reported. A class written "[!a]" is
// unloadable for the same reason: the negation AppArmor accepts is "[^a]",
// and a literal "!" in a class has to be escaped (`[\!a]`).
//
// A path holding a NUL byte, or an escape denoting one such as \000, \x00 or
// \d000, loads but matches nothing, since no name the kernel hands AppArmor
// holds a NUL; it is reported with [ErrNulInPath]. A path with a "." or ".."
// component matches nothing either and is reported with [ErrDotComponent].
// In a glob, the components of the literal text before the first glob token
// count, and so do later components that are exactly "." or ".." outside
// every alternation and class: "/a/*/../b" is reported, while "/{a,b/./c}"
// is not, as its "/a" alternative can match. A path that does not start
// with "/" is reported with [ErrRelativePath], since file rules must use
// absolute paths.
//
// # Filesystem merge
//
// Paths are expanded into read and write permissions, merged per path (AND
// for intersection, OR for union), and collapsed back into read-only,
// write-only and read-write lists. A read-write path intersected with a
// read-only one becomes read-only; a read-only path in one profile and
// write-only in the other is dropped on intersection but becomes read-write
// on union.
//
// On intersection a literal path survives when a glob on the other side
// matches it, and two globs survive only when they are identical or one is
// the "**" expansion of a non-empty literal prefix containing the other's
// prefix (so "/etc/**" narrows to "/etc/*.conf" and to "/etc/foo/*.conf").
// As "<prefix>**" requires a character after the prefix, a glob that can
// match the prefix itself is not narrowed by it: "/etc/**" and "/etc/{,**}"
// intersect to nothing. The narrowing guarantee is over canonical paths, the
// only names AppArmor matches: a glob whose literal prefix spells "//" with
// an escaped slash (`/etc/\/foo/*`) is not narrowed, while one that spells a
// "/" after a "/" inside an alternation or class (`/etc/{\/a,b}`,
// "/etc/[/]x") is narrowed and may match a name containing "//" that the
// "**" pattern does not.
//
// On union every glob of either profile is kept, and globs never prune
// other globs. Globs prune the literals of the other profile they match: a
// literal only one profile lists is dropped when the other profile's globs
// grant everything it grants. When those globs grant only part of it, the
// literal also takes their permissions, so a write-only literal under a
// read-only glob of the other profile becomes read-write. A literal both
// profiles list is kept with the permissions they list. A profile's own
// globs never prune or promote its own literals, so a single profile's paths
// are kept as written (Union(p, p) keeps the paths of p), and the result
// depends neither on the order of the two profiles nor on the order of the
// paths within them.
//
// More than two profiles are folded from left to right, and with patterns
// involved the result depends on that order: a pattern survives only where
// the other side spells it alike or expands over it, so two patterns that
// cover one literal without covering each other cancel out when they are
// folded first, taking the literal with them. Intersect(a, b, c) may
// therefore permit more or less than Intersect(a, Intersect(b, c)). Every
// grouping is safe: whatever the order, the result permits only what every
// input permits, and the difference is which of the permitted paths survive
// as rules.
//
// # Nil and empty sections
//
// A nil field means the profile says nothing about that section, which to
// AppArmor denies everything the section covers. Intersect treats a nil
// section as an explicit empty one and a nil network boolean as false, so
// intersecting {caps: [NET_ADMIN]} with {caps: nil} yields [] just as
// intersecting with {caps: []} does, and the result carries every section
// explicitly; when no paths overlap, the result holds an empty
// FilesystemRules. Union lets a nil section defer to the other profile,
// which grants the same as an empty section would; only the shape of the
// result differs, as a section nil on both sides stays nil.
//
// Diff compares the same way, so a profile that says nothing about raw
// sockets and one that forbids them are equal, and Diff(p, Intersect(p)) is
// equal unless p has patterns that match nothing, which the intersection
// drops: the explicit sections an intersection writes are not reported as a
// change.
//
// # Cost bounds
//
// Matching literals against patterns costs one comparison per pair, and the
// prefix index only separates patterns rooted in different directories, so
// a profile whose patterns share one prefix costs the product of the two
// path counts. One comparison in turn costs up to the length of the pattern
// times the length of the name, so the work summed over every pair is up to
// the product of the bytes the two sides hold. Both merges bound the number
// of pairs (the pair budget) and that work (the work budget). Past either
// budget an intersection keeps only the paths both sides spell alike, which
// permits no more than the exact intersection would, and a union keeps
// every path of both sides with the permissions its own side grants, which
// permits exactly what the reduced union does: the literals the reduction
// drops or raises are the ones a pattern of the other side already covers,
// and that pattern is kept either way.
//
// [MaxArtifactPaths] keeps two artifacts inside the pair budget, and keeps
// an artifact whose paths are a few dozen bytes long inside the work budget
// against a baseline of a few kilobytes of paths. Two artifacts of that size
// merged with each other, or a profile of long paths, may exceed the work
// budget and be merged conservatively instead.
//
// # Concurrency
//
// Every exported function is safe to call from several goroutines at once.
// The functions never modify their arguments, except UnmarshalStrict, which
// replaces the profile it is given when decoding succeeds. The package keeps
// one internal cache of compiled glob patterns, guarded by its own lock,
// which is the only state shared between calls; it changes no result, only
// the work a repeated pattern costs. It does hold the pattern text of the
// profiles it compiled, bounded by its own size limits and evicted as newer
// patterns arrive, so a process merging artifacts keeps some of their paths
// in memory after a call returns. Concurrent calls only need their profiles
// not to be written to at the same time from elsewhere.
package apparmor
