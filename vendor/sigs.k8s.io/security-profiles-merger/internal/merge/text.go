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

package merge

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// SafeText returns a value taken from a profile as it can be printed. A
// value holding a control character or a byte that is not valid UTF-8 is
// quoted, which spells those bytes out; every other value is returned as it
// is, so that the usual rendering of a profile is unchanged.
//
// The formatters write into a runtime's log and onto an operator's terminal.
// A path or a syscall name of an artifact is chosen by its author, and a
// newline in one forges a log line while an escape sequence moves the cursor
// or repaints what is already on screen. The validators already report every
// value this way (see QuoteBounded); this is the same rule for the values a
// result carries rather than the ones a failure names.
func SafeText(value string) string {
	if printableText(value) {
		return value
	}

	return strconv.Quote(value)
}

// SafeTexts applies SafeText to each of the values, returning the slice
// itself when none of them needs it.
func SafeTexts(values []string) []string {
	needed := false

	for _, value := range values {
		if !printableText(value) {
			needed = true

			break
		}
	}

	if !needed {
		return values
	}

	safe := make([]string, len(values))
	for idx, value := range values {
		safe[idx] = SafeText(value)
	}

	return safe
}

// printableText reports whether a value can be written as it is: valid
// UTF-8 whose every rune strconv.Quote would leave alone. That is the same
// line QuoteBounded draws, so a value the validators quote is a value the
// formatters quote: besides the C0 controls and DEL it covers the C1
// controls and the format characters, such as U+202E, which reorder what is
// already on screen without moving the cursor.
func printableText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}

	return strings.IndexFunc(value, func(char rune) bool {
		return !strconv.IsPrint(char)
	}) < 0
}
