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

package e2e_test

// The helpers of the sharding of the test cases, see E2E_SHARD, build without
// the e2e build tag, so that their unit tests run without a cluster:
// go test ./test.

import (
	"cmp"
	"flag"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// testShard is one of the shards which split the test cases of the suite
// between CI jobs, see E2E_SHARD. The zero value runs all test cases.
type testShard struct {
	// index is the number of the shard, starting at 1.
	index int
	// total is the number of shards, zero if the test cases are not split.
	total int
}

// parseTestShard parses INDEX/TOTAL, the index starting at 1. An empty value
// runs all test cases.
func parseTestShard(value string) (testShard, error) {
	if value == "" {
		return testShard{}, nil
	}

	index, total, ok := strings.Cut(value, "/")
	if !ok {
		return testShard{}, fmt.Errorf("shard %q is not INDEX/TOTAL", value)
	}

	shard := testShard{}

	var err error
	if shard.index, err = strconv.Atoi(index); err != nil {
		return testShard{}, fmt.Errorf("index of shard %q: %w", value, err)
	}

	if shard.total, err = strconv.Atoi(total); err != nil {
		return testShard{}, fmt.Errorf("total of shard %q: %w", value, err)
	}

	if shard.index < 1 || shard.index > shard.total {
		return testShard{}, fmt.Errorf("shard %q is not between 1/%d and %d/%d",
			value, shard.total, shard.total, shard.total)
	}

	return shard, nil
}

func (s testShard) String() string {
	return fmt.Sprintf("%d/%d", s.index, s.total)
}

// assignTestShards assigns each weight to one of total shards and returns the
// shard of each, starting at 1. The heaviest get assigned first, each to the
// shard with the least weight so far, which balances the shards. The
// assignment only depends on the weights and their order, so every shard
// computes the same one.
func assignTestShards(weights []time.Duration, total int) []int {
	order := make([]int, len(weights))
	for i := range order {
		order[i] = i
	}

	// Stable, so that equal weights keep their order.
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(weights[b], weights[a])
	})

	loads := make([]time.Duration, total)
	shards := make([]int, len(weights))

	for _, i := range order {
		lightest := 0

		for shard := range loads {
			if loads[shard] < loads[lightest] {
				lightest = shard
			}
		}

		loads[lightest] += weights[i]
		shards[i] = lightest + 1
	}

	return shards
}

// testNamePattern matches the names of tests like the -test.run and
// -test.skip patterns do, see matcher.go of the testing package: the pattern
// is split at the bars and the slashes outside of brackets and parentheses,
// into alternatives of one regular expression per element of the name.
type testNamePattern [][]*regexp.Regexp

// compileTestNamePattern compiles the pattern, nil for an empty one.
func compileTestNamePattern(pattern string) (testNamePattern, error) {
	if pattern == "" {
		return nil, nil
	}

	var (
		alternatives testNamePattern
		elements     []*regexp.Regexp
		brackets     int
		parentheses  int
	)

	add := func(element string) error {
		re, err := regexp.Compile(element)
		if err != nil {
			return fmt.Errorf("element %q of test name pattern %q: %w", element, pattern, err)
		}

		elements = append(elements, re)

		return nil
	}

	start := 0

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[':
			brackets++
		case ']':
			// An unmatched ] is a literal.
			brackets = max(brackets-1, 0)
		case '(':
			if brackets == 0 {
				parentheses++
			}
		case ')':
			if brackets == 0 {
				parentheses--
			}
		case '\\':
			i++
		case '/', '|':
			if brackets != 0 || parentheses != 0 {
				continue
			}

			if err := add(pattern[start:i]); err != nil {
				return nil, err
			}

			start = i + 1

			if pattern[i] == '|' {
				alternatives = append(alternatives, elements)
				elements = nil
			}
		}
	}

	if err := add(pattern[start:]); err != nil {
		return nil, err
	}

	return append(alternatives, elements), nil
}

// matches reports whether the pattern matches the name of a test, whose sub
// tests are separated by slashes. partial is set if the name only matches the
// first elements of the pattern, so that the pattern may match its sub tests.
func (p testNamePattern) matches(name string) (ok, partial bool) {
	elements := strings.Split(name, "/")

	for _, alternative := range p {
		matched := true

		for i, element := range elements {
			if i >= len(alternative) {
				break
			}

			if !alternative[i].MatchString(element) {
				matched = false

				break
			}
		}

		if matched {
			return true, len(elements) < len(alternative)
		}
	}

	return false, false
}

// testSkipped reports whether the -test.skip pattern skip, nil if it is not
// set, skips the test of the name. Like the testing package, it skips a test
// if the pattern matches the name fully.
func testSkipped(name string, skip testNamePattern) bool {
	if skip == nil {
		return false
	}

	ok, partial := skip.matches(name)

	return ok && !partial
}

// testCaseShards returns the shard of each of the test cases of the names and
// durations, see assignTestShards, where a test case which the -test.skip flag
// skips weighs nothing. The -test.run flag is left out on purpose: gotestsum
// retries a failed test case with a -test.run pattern of only that test case,
// which has to run in the same shard as before, and the testing package
// leaves out the test cases the pattern does not select anyway.
func testCaseShards(names []string, durations []time.Duration, total int) []int {
	skip := testFlagPattern("test.skip")
	weights := slices.Clone(durations)

	for i, name := range names {
		if testSkipped(name, skip) {
			weights[i] = 0
		}
	}

	return assignTestShards(weights, total)
}

// testFlagPattern returns the pattern of the -test.run or -test.skip flag,
// nil if it is not set. The testing package fails on an invalid pattern
// before any test runs, so this one gets ignored.
func testFlagPattern(name string) testNamePattern {
	f := flag.Lookup(name)
	if f == nil {
		return nil
	}

	pattern, err := compileTestNamePattern(f.Value.String())
	if err != nil {
		return nil
	}

	return pattern
}

// subTestName returns the name the testing package gives a sub test of the
// description: the spaces get replaced with underscores. The descriptions of
// the test cases only consist of printable characters, which it keeps.
func subTestName(description string) string {
	return strings.ReplaceAll(description, " ", "_")
}
