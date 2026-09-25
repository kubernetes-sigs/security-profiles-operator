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
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file ports the stages apparmor_parser runs a file rule's path
// through, so that a pattern means here what it means to AppArmor:
//
//  1. processunquoted (parser_misc.c) resolves escape sequences, keeping
//     pattern metacharacters escaped.
//  2. filter_slashes (parser_regex.c) collapses repeated slashes.
//  3. convert_aaregex_to_pcre (parser_regex.c) translates the AppArmor
//     pattern into the regex dialect of libapparmor_re.
//  4. regex_lex and the grammar in libapparmor_re/parse.y parse that regex
//     into the byte-oriented expression tree the DFA is built from.
//
// The port produces a Go regular expression that matches exactly the byte
// strings the DFA accepts, with every byte of a name mapped to the rune of
// the same value (see latin1). Constructs whose parser behavior is an
// accident of the translation rather than a meaningful pattern are reported
// as invalid instead of being modeled; see convertPattern.

// patternKind classifies a path after conversion.
type patternKind int

const (
	// kindLiteral is a path without glob tokens: it names a single file.
	kindLiteral patternKind = iota
	// kindGlob is a pattern with glob tokens.
	kindGlob
	// kindInvalid is a pattern apparmor_parser rejects, or accepts with a
	// meaning this package does not model.
	kindInvalid
)

const (
	// maxAltDepth is MAX_ALT_DEPTH of convert_aaregex_to_pcre: a pattern
	// whose "{" nesting reaches it is rejected.
	maxAltDepth = 50
	// maxEscapeDigits bounds the digits of an octal or decimal escape;
	// maxHexDigits bounds those of a hex escape.
	maxEscapeDigits = 3
	maxHexDigits    = 2
	maxEscapeValue  = 255
	octalBase       = 8
	decimalBase     = 10
	hexBase         = 16
	letterDigitBase = 10
	byteValues      = 256
)

// lexerEscapes are the characters regex_lex accepts after a backslash as
// themselves.
const lexerEscapes = `*+.|^$-[](){}`

// reescaped are the characters processunquoted keeps escaped when an escape
// sequence resolves to them, so that they stay literal.
const reescaped = `*?[]{}^,\`

// digitValue ports chrtoi: the value of a digit in the given base, or -1.
func digitValue(char byte, base int) int {
	val := -1

	switch {
	case char >= '0' && char <= '9':
		val = int(char - '0')
	case char >= 'a' && char <= 'z':
		val = int(char-'a') + letterDigitBase
	case char >= 'A' && char <= 'Z':
		val = int(char-'A') + letterDigitBase
	}

	if val >= base {
		return -1
	}

	return val
}

// parseNumber ports strntol: it reads at most maxDigits digits of the base
// starting at pos, stopping before the value would exceed 255, and returns
// the value and the index after the digits read.
func parseNumber(text string, pos, base, maxDigits int) (byte, int) {
	var val byte

	for ; maxDigits > 0 && pos < len(text); pos, maxDigits = pos+1, maxDigits-1 {
		digit := digitValue(text[pos], base)
		if digit < 0 {
			break
		}

		next := int(val)*base + digit
		if next > maxEscapeValue {
			break
		}

		val = byteValue(next)
	}

	return val, pos
}

// byteValue converts a value known to be in the byte range.
func byteValue(val int) byte {
	return byte(min(max(val, 0), maxEscapeValue))
}

// namedEscape returns the byte an escape character strn_escseq resolves on
// its own denotes.
func namedEscape(char byte) (byte, bool) {
	const named = "\\\\\"\"a\ae\x1bf\fn\nr\rt\t"

	for idx := 0; idx < len(named); idx += 2 {
		if named[idx] == char {
			return named[idx+1], true
		}
	}

	return 0, false
}

// escapeSequence ports strn_escseq for the escape whose first character
// after the backslash is at pos. It returns the byte the sequence denotes
// and the index after it, or false when the sequence is not one the parser
// resolves. extra lists the characters that denote themselves.
func escapeSequence(text string, pos int, extra string) (byte, int, bool) {
	if pos >= len(text) {
		return 0, pos, false
	}

	char := text[pos]

	switch {
	case char >= '0' && char <= '7':
		val, end := parseNumber(text, pos, octalBase, maxEscapeDigits)

		return val, end, true
	case char == 'd':
		val, end := parseNumber(text, pos+1, decimalBase, maxEscapeDigits)

		return val, end, end > pos+1
	case char == 'x':
		val, end := parseNumber(text, pos+1, hexBase, maxHexDigits)

		return val, end, end > pos+1
	}

	if val, named := namedEscape(char); named {
		return val, pos + 1, true
	}

	return char, pos + 1, strings.IndexByte(extra, char) >= 0
}

// decodeEscapes ports processunquoted, which the parser's lexer applies to
// every path: escape sequences are resolved, except that a sequence denoting
// a pattern metacharacter stays escaped and one denoting NUL is kept as
// written.
func decodeEscapes(raw string) string {
	if strings.IndexByte(raw, '\\') < 0 {
		return raw
	}

	var builder strings.Builder

	builder.Grow(len(raw))

	for pos := 0; pos < len(raw); {
		if raw[pos] == '\\' && pos+1 < len(raw) {
			if val, end, ok := escapeSequence(raw, pos+1, ""); ok {
				switch {
				case val == 0:
					builder.WriteString(raw[pos:end])
				case strings.IndexByte(reescaped, val) >= 0:
					builder.WriteByte('\\')
					builder.WriteByte(val)
				default:
					builder.WriteByte(val)
				}

				pos = end

				continue
			}
		}

		builder.WriteByte(raw[pos])
		pos++
	}

	return builder.String()
}

// filterSlashes ports filter_slashes: runs of "/" collapse into one, except
// that a leading "//" not followed by a third slash is kept. The parser
// neither removes a trailing slash nor resolves "." or ".." components.
func filterSlashes(path string) string {
	if !strings.Contains(path, "//") {
		return path
	}

	var builder strings.Builder

	builder.Grow(len(path))

	start := 0

	if strings.HasPrefix(path, "//") && (len(path) == 2 || path[2] != '/') {
		builder.WriteString("//")

		start = 2
	}

	seenSlash := false

	for pos := start; pos < len(path); pos++ {
		if path[pos] == '/' {
			if !seenSlash {
				builder.WriteByte('/')
			}

			seenSlash = true

			continue
		}

		seenSlash = false

		builder.WriteByte(path[pos])
	}

	return builder.String()
}

// filterRawSlashes collapses repeated slashes in a path as written, before
// its escape sequences are resolved, so that the result means to the parser
// what the path does. The parser resolves escapes first and filters slashes
// after (see decodeEscapes and filterSlashes), so an escape denoting "/", as
// in `\x2f`, `\057` or `\d047`, counts as a slash of the run it borders:
// `///\x2fetc` names "/etc", not "//etc". Each run keeps its first slash as
// written and drops the rest, and a leading run of exactly two slashes is
// kept whole, as filterSlashes does. Other escapes are left as written.
func filterRawSlashes(path string) string {
	if strings.IndexByte(path, '\\') < 0 {
		return filterSlashes(path)
	}

	units := rawUnits(path)

	var builder strings.Builder

	builder.Grow(len(path))

	start := 0

	if len(units) >= 2 && units[0].slash && units[1].slash &&
		(len(units) == 2 || !units[2].slash) {
		builder.WriteString(path[:units[1].end])

		start = 2
	}

	seenSlash := false

	for _, current := range units[start:] {
		if !current.slash || !seenSlash {
			builder.WriteString(path[current.start:current.end])
		}

		seenSlash = current.slash
	}

	return builder.String()
}

// rawUnit is a part of a path as written that decodeEscapes turns into one
// piece of its result: an escape sequence it resolves, or a single byte.
type rawUnit struct {
	start, end int
	// slash reports that the unit denotes "/".
	slash bool
}

// rawUnits splits a path into the units decodeEscapes reads it as.
func rawUnits(path string) []rawUnit {
	units := make([]rawUnit, 0, len(path))

	for pos := 0; pos < len(path); {
		if path[pos] == '\\' && pos+1 < len(path) {
			if val, end, ok := escapeSequence(path, pos+1, ""); ok {
				units = append(units, rawUnit{start: pos, end: end, slash: val == '/'})
				pos = end

				continue
			}
		}

		units = append(units, rawUnit{start: pos, end: pos + 1, slash: path[pos] == '/'})
		pos++
	}

	return units
}

// conversion is the result of convertPattern.
type conversion struct {
	// regex is the pattern in libapparmor_re syntax.
	regex string
	kind  patternKind
	// literalEnd is the length of the regex prefix emitted before the first
	// glob token, which consists of literal characters only. It is the
	// whole regex for a literal path.
	literalEnd int
	// alternatives is the total number of alternatives across all
	// alternations.
	alternatives int
	// starStarOnly reports that the only glob token is a trailing "**"
	// directly after a "/", which makes the pattern the expansion of its
	// literal prefix.
	starStarOnly bool
}

// converter holds the state of convert_aaregex_to_pcre.
type converter struct {
	pattern   string
	regex     strings.Builder
	escaped   bool
	grouping  int
	counts    [maxAltDepth]int
	inClass   bool
	classOpen int
	firstGlob int
	// globs counts the glob tokens seen.
	globs int
	// trailingStarStar reports a "**" that ends the pattern and starts a
	// path component.
	trailingStarStar bool
	result           conversion
}

// convertPattern ports convert_aaregex_to_pcre for a file rule. Beyond the
// errors the parser reports (an unclosed or unopened "{" or "[", a "{...}"
// without a comma, "{" nested 50 deep, and a trailing backslash), it treats
// as invalid three constructs the parser accepts but translates into
// something other than what the pattern says:
//
//   - "*" or "?" inside a character class, which the parser expands into a
//     nested class, ending the enclosing one early;
//   - a class whose content is empty or a lone "^" (such as "[]" or "[^]"),
//     whose closing bracket libapparmor_re takes as a member, so the class
//     extends to a later bracket;
//   - an escaped "," inside a class, which libapparmor_re's lexer turns into
//     a literal backslash class member rather than the comma it spells (on a
//     bad escape parse.y sets the character to a backslash and returns it),
//     and which loops on current upstream master, where strn_escseq restores
//     the position on failure and regex_lex decrements it again.
//
// A pattern with such a construct matches nothing in this package, and
// ValidateArtifact and ValidateStrict report it.
func convertPattern(pattern string) conversion {
	conv := converter{
		pattern:          pattern,
		regex:            strings.Builder{},
		escaped:          false,
		grouping:         0,
		counts:           [maxAltDepth]int{},
		inClass:          false,
		classOpen:        0,
		firstGlob:        -1,
		globs:            0,
		trailingStarStar: false,
		result: conversion{
			regex:        "",
			kind:         kindInvalid,
			literalEnd:   0,
			alternatives: 0,
			starStarOnly: false,
		},
	}
	conv.regex.Grow(len(pattern))

	// A C string ends at the first NUL, so a path containing one cannot be
	// written into a profile.
	valid := strings.IndexByte(pattern, 0) < 0
	for pos := 0; valid && pos < len(pattern); pos++ {
		pos, valid = conv.step(pos)
	}

	conv.result.regex = conv.regex.String()

	if !valid || conv.grouping > 0 || conv.inClass || conv.escaped {
		return conv.result
	}

	if conv.firstGlob < 0 {
		conv.result.kind = kindLiteral
		conv.result.literalEnd = len(conv.result.regex)

		return conv.result
	}

	conv.result.kind = kindGlob
	conv.result.literalEnd = conv.firstGlob
	conv.result.starStarOnly = conv.trailingStarStar && conv.globs == 1

	return conv.result
}

// markGlob records the position of the first glob token, as update_re_pos
// does.
func (conv *converter) markGlob() {
	conv.globs++

	if conv.firstGlob < 0 {
		conv.firstGlob = conv.regex.Len()
	}
}

// step converts the character at pos and returns the index of the last
// character consumed, and false on an error.
func (conv *converter) step(pos int) (int, bool) {
	char := conv.pattern[pos]
	escaped := conv.escaped
	conv.escaped = false

	if char == '\\' && !escaped {
		conv.escaped = true

		return pos, true
	}

	switch char {
	case '*':
		return conv.star(pos, escaped)
	case '?':
		return pos, conv.question(escaped)
	case '[', ']':
		return pos, conv.bracket(char, escaped)
	case '{', '}':
		return pos, conv.brace(char, escaped)
	case ',':
		return pos, conv.comma(escaped)
	}

	return conv.literal(pos, escaped), true
}

// literal converts a character that is not a glob token and returns the
// index of the last character consumed.
func (conv *converter) literal(pos int, escaped bool) int {
	char := conv.pattern[pos]

	switch {
	case char == '\\':
		// Only an escaped backslash gets here.
		conv.regex.WriteString(`\\`)
	case char == '^' || char == '$':
		if !conv.inClass {
			conv.regex.WriteByte('\\')
		}

		conv.regex.WriteByte(char)
	case strings.IndexByte(".+|()", char) >= 0:
		conv.regex.WriteByte('\\')
		conv.regex.WriteByte(char)
	default:
		return conv.plain(pos, escaped)
	}

	return pos
}

// startsComponent reports whether the star run at pos fills a whole path
// component, in which case the parser requires it to match a character: the
// last character emitted is "/", and the run is followed by "/" or ends the
// pattern. Only the raw next character counts, so a run followed by "," or
// "}" inside an alternation requires nothing.
func (conv *converter) startsComponent(pos int) bool {
	regex := conv.regex.String()
	if regex == "" || regex[len(regex)-1] != '/' {
		return false
	}

	next := pos
	for next < len(conv.pattern) && conv.pattern[next] == '*' {
		next++
	}

	return next == len(conv.pattern) || conv.pattern[next] == '/'
}

func (conv *converter) star(pos int, escaped bool) (int, bool) {
	if escaped {
		conv.regex.WriteString(`\*`)

		return pos, true
	}

	if conv.inClass {
		return pos, false
	}

	conv.markGlob()

	componentStart := conv.startsComponent(pos)
	if componentStart {
		conv.regex.WriteString(`[^/\x00]`)
	}

	// A run of two or more stars is one "**": the parser emits a second
	// "[^/\x00]*" for a third star, which matches the same names as the
	// "[^\x00]*" before it already does, so the run says nothing more than
	// "**" says. Counting it as one glob token is what lets a pattern
	// spelled "/etc/***" narrow another pattern the way "/etc/**" does,
	// rather than silently dropping it from an intersection.
	runEnd := pos
	for runEnd+1 < len(conv.pattern) && conv.pattern[runEnd+1] == '*' {
		runEnd++
	}

	if runEnd > pos {
		conv.trailingStarStar = componentStart && runEnd+1 == len(conv.pattern)
		conv.regex.WriteString(`[^\x00]*`)

		return runEnd, true
	}

	conv.regex.WriteString(`[^/\x00]*`)

	return pos, true
}

func (conv *converter) question(escaped bool) bool {
	if escaped {
		conv.regex.WriteByte('?')

		return true
	}

	if conv.inClass {
		return false
	}

	conv.markGlob()
	conv.regex.WriteString(`[^/\x00]`)

	return true
}

func (conv *converter) bracket(char byte, escaped bool) bool {
	if escaped {
		conv.regex.WriteByte('\\')
		conv.regex.WriteByte(char)

		return true
	}

	if char == '[' {
		conv.markGlob()

		if !conv.inClass {
			conv.classOpen = conv.regex.Len()
		}

		conv.inClass = true
		conv.regex.WriteByte('[')

		return true
	}

	if !conv.inClass {
		return false
	}

	content := conv.regex.String()[conv.classOpen+1:]
	if content == "" || content == "^" {
		return false
	}

	conv.inClass = false
	conv.regex.WriteByte(']')

	return true
}

func (conv *converter) brace(char byte, escaped bool) bool {
	switch {
	case escaped:
		conv.regex.WriteByte('\\')
		conv.regex.WriteByte(char)
	case conv.inClass:
		conv.regex.WriteByte(char)
	case char == '{':
		conv.markGlob()

		conv.grouping++
		if conv.grouping >= maxAltDepth {
			return false
		}

		conv.counts[conv.grouping] = 0
		conv.regex.WriteByte('(')
	default:
		if conv.grouping == 0 || conv.counts[conv.grouping] == 0 {
			return false
		}

		conv.result.alternatives += conv.counts[conv.grouping] + 1
		conv.grouping--
		conv.regex.WriteByte(')')
	}

	return true
}

func (conv *converter) comma(escaped bool) bool {
	switch {
	case escaped && conv.inClass:
		return false
	case escaped:
		conv.regex.WriteByte(',')
	case conv.grouping > 0 && !conv.inClass:
		conv.counts[conv.grouping]++
		conv.regex.WriteByte('|')
	default:
		conv.regex.WriteByte(',')
	}

	return true
}

// plain converts an ordinary character, resolving an escape sequence that
// starts at it.
func (conv *converter) plain(pos int, escaped bool) int {
	if !escaped {
		conv.regex.WriteByte(conv.pattern[pos])

		return pos
	}

	if _, end, ok := escapeSequence(conv.pattern, pos, ""); ok {
		conv.regex.WriteByte('\\')
		conv.regex.WriteString(conv.pattern[pos:end])

		return end - 1
	}

	conv.regex.WriteByte(conv.pattern[pos])

	return pos
}

// regexToken is one token of libapparmor_re's regex lexer.
type regexToken struct {
	// char is the character the token denotes.
	char byte
	// special reports an unescaped metacharacter.
	special bool
}

// lexRegex ports regex_lex: it returns the token at pos and the index after
// it, and false for an escape the lexer cannot handle.
func lexRegex(regex string, pos int) (regexToken, int, bool) {
	char := regex[pos]

	switch char {
	case '*', '+', '.', '|', '^', '-', '[', ']', '(', ')':
		return regexToken{char: char, special: true}, pos + 1, true
	case '\\':
		val, end, ok := escapeSequence(regex, pos+1, lexerEscapes)
		if !ok {
			return regexToken{char: 0, special: false}, pos, false
		}

		return regexToken{char: val, special: false}, end, true
	}

	return regexToken{char: char, special: false}, pos + 1, true
}

// literalBytes returns the bytes a regex made of literal tokens denotes.
func literalBytes(regex string) string {
	var builder strings.Builder

	builder.Grow(len(regex))

	for pos := 0; pos < len(regex); {
		token, end, ok := lexRegex(regex, pos)
		if !ok {
			break
		}

		builder.WriteByte(token.char)

		pos = end
	}

	return builder.String()
}

// regexParser ports the grammar of libapparmor_re/parse.y, emitting an
// equivalent Go regular expression over latin1-mapped names.
type regexParser struct {
	regex string
	pos   int
	out   strings.Builder
}

// translateRegex translates a libapparmor_re regex into Go syntax, or
// reports false when libapparmor_re would fail to parse it.
func translateRegex(regex string) (string, bool) {
	parser := regexParser{regex: regex, pos: 0, out: strings.Builder{}}
	parser.out.Grow(len(regex))

	if !parser.alternation() || parser.pos != len(regex) {
		return "", false
	}

	return parser.out.String(), true
}

// peek returns the token at the current position, with ok false at the end
// of the regex or on a lexer error.
func (parser *regexParser) peek() (regexToken, int, bool) {
	if parser.pos >= len(parser.regex) {
		return regexToken{char: 0, special: false}, parser.pos, false
	}

	return lexRegex(parser.regex, parser.pos)
}

// atSpecial reports whether the next token is the given metacharacter.
func (parser *regexParser) atSpecial(char byte) bool {
	token, _, found := parser.peek()

	return found && token.special && token.char == char
}

// alternation parses "regex": terms separated by "|", each possibly empty.
func (parser *regexParser) alternation() bool {
	parser.out.WriteString("(?:")

	for {
		if !parser.terms() {
			return false
		}

		if !parser.atSpecial('|') {
			break
		}

		parser.pos++

		parser.out.WriteByte('|')
	}

	parser.out.WriteByte(')')

	return true
}

// terms parses a possibly empty sequence of optionally quantified terms,
// ending before "|", ")", or the end of the regex.
func (parser *regexParser) terms() bool {
	for parser.pos < len(parser.regex) {
		token, _, found := parser.peek()
		if !found {
			return false
		}

		if token.special && (token.char == '|' || token.char == ')') {
			return true
		}

		if !parser.term() {
			return false
		}

		if parser.atSpecial('*') || parser.atSpecial('+') {
			parser.out.WriteByte(parser.regex[parser.pos])
			parser.pos++
		}
	}

	return true
}

// term parses one term, each emitted as a group so a quantifier applies to
// all of it.
func (parser *regexParser) term() bool {
	token, end, _ := parser.peek()
	parser.pos = end

	if !token.special {
		parser.out.WriteString(byteFragment(token.char))

		return true
	}

	switch token.char {
	case '^', '-', ']':
		parser.out.WriteString(byteFragment(token.char))

		return true
	case '[':
		return parser.class()
	case '(':
		if !parser.alternation() || !parser.atSpecial(')') {
			return false
		}

		parser.pos++

		return true
	case '.':
		parser.out.WriteString(`(?:[\x00-\x{ff}])`)

		return true
	}

	return false
}

// classMember reads a class member: any non-special token, a special token
// the grammar accepts as a member, or nothing.
func (parser *regexParser) classMember(allowed string) (byte, bool) {
	token, end, ok := parser.peek()
	if !ok {
		return 0, false
	}

	if token.special && strings.IndexByte(allowed, token.char) < 0 {
		return 0, false
	}

	parser.pos = end

	return token.char, true
}

const (
	// csetChar are the metacharacters cset_char accepts.
	csetChar = "[*+.|()"
	// csetCharN adds what cset_charN accepts.
	csetCharN = csetChar + "^"
	// csetChar1 adds what cset_char1 accepts.
	csetChar1 = csetChar + "]-"
)

// class parses a character class after its "[".
func (parser *regexParser) class() bool {
	var members [byteValues]bool

	negated := false

	if parser.atSpecial('^') {
		negated = true
		parser.pos++

		if parser.atSpecial('^') {
			parser.pos++
			members['^'] = true

			if !parser.classRest(&members) {
				return false
			}

			return parser.closeClass(&members, negated)
		}
	}

	first, ok := parser.classMember(csetChar1)
	if !ok {
		return false
	}

	if !parser.rangeFrom(first, &members) {
		return false
	}

	if !parser.classRest(&members) {
		return false
	}

	return parser.closeClass(&members, negated)
}

// rangeFrom adds low to the class, or the range it starts when a "-"
// follows.
func (parser *regexParser) rangeFrom(low byte, members *[byteValues]bool) bool {
	if !parser.atSpecial('-') {
		members[low] = true

		return true
	}

	parser.pos++

	high, ok := parser.classMember(csetCharN)
	if !ok {
		return false
	}

	// insert_char_range swaps reversed bounds.
	low, high = min(low, high), max(low, high)
	for char := int(low); char <= int(high); char++ {
		members[char] = true
	}

	return true
}

// classRest parses cset_chars: members and ranges up to the closing "]".
func (parser *regexParser) classRest(members *[byteValues]bool) bool {
	for {
		token, _, found := parser.peek()
		if !found {
			return false
		}

		if token.special && token.char == ']' {
			return true
		}

		char, ok := parser.classMember(csetCharN)
		if !ok {
			return false
		}

		if !parser.rangeFrom(char, members) {
			return false
		}
	}
}

// closeClass consumes the closing "]" and emits the class.
func (parser *regexParser) closeClass(members *[byteValues]bool, negated bool) bool {
	if !parser.atSpecial(']') {
		return false
	}

	parser.pos++

	parser.out.WriteString(classFragment(members, negated))

	return true
}

// neverMatchFragment is a Go regex fragment that matches nothing.
const neverMatchFragment = `[^\x00-\x{10FFFF}]`

// classFragment renders a byte set as a Go character class over the runes
// 0 to 255. A negated libapparmor_re class matches every byte outside the
// set.
func classFragment(members *[byteValues]bool, negated bool) string {
	var builder strings.Builder

	builder.WriteByte('[')

	empty := true

	for low := 0; low < byteValues; {
		if members[low] == negated {
			low++

			continue
		}

		high := low
		for high+1 < byteValues && members[high+1] != negated {
			high++
		}

		empty = false

		builder.WriteString(runeEscape(byte(low)))

		if high > low {
			builder.WriteByte('-')
			builder.WriteString(runeEscape(byte(high)))
		}

		low = high + 1
	}

	if empty {
		return neverMatchFragment
	}

	builder.WriteByte(']')

	return builder.String()
}

// runeEscape renders a byte as a Go regex rune escape.
func runeEscape(char byte) string {
	return `\x{` + strconv.FormatUint(uint64(char), hexBase) + `}`
}

// byteFragment renders a literal byte for a Go regex.
func byteFragment(char byte) string {
	if char < utf8.RuneSelf && char > ' ' && char != 0x7f {
		return quoteByte(char)
	}

	return runeEscape(char)
}

// quoteByte escapes a printable ASCII byte if Go's regex syntax needs it.
func quoteByte(char byte) string {
	if strings.IndexByte(`\.+*?()|[]{}^$`, char) >= 0 {
		return `\` + string(rune(char))
	}

	return string(rune(char))
}

// latin1 maps every byte of a name to the rune of the same value, which is
// what the translated regexes match, since AppArmor matches bytes rather
// than characters.
func latin1(name string) string {
	ascii := true

	for idx := range len(name) {
		if name[idx] >= utf8.RuneSelf {
			ascii = false

			break
		}
	}

	if ascii {
		return name
	}

	runes := make([]rune, len(name))
	for idx := range len(name) {
		runes[idx] = rune(name[idx])
	}

	return string(runes)
}
