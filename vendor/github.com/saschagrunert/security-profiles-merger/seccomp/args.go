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

package seccomp

import (
	"cmp"
	"math"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// sortedArgs returns a sorted copy of the argument filters.
func sortedArgs(args []specs.LinuxSeccompArg) []specs.LinuxSeccompArg {
	if len(args) == 0 {
		return nil
	}

	cloned := slices.Clone(args)
	sortArgs(cloned)

	return cloned
}

func sortArgs(args []specs.LinuxSeccompArg) {
	slices.SortFunc(args, func(left, right specs.LinuxSeccompArg) int {
		return cmp.Or(
			cmp.Compare(left.Index, right.Index),
			cmp.Compare(left.Value, right.Value),
			cmp.Compare(left.ValueTwo, right.ValueTwo),
			cmp.Compare(left.Op, right.Op),
		)
	})
}

// argsKey returns a canonical string for a set of argument filters so that
// filters differing only in order compare equal. Empty args yield "".
func argsKey(args []specs.LinuxSeccompArg) string {
	if len(args) == 0 {
		return ""
	}

	var builder strings.Builder

	for _, arg := range sortedArgs(args) {
		builder.WriteString(strconv.FormatUint(uint64(arg.Index), 10))
		builder.WriteByte(':')
		builder.WriteString(string(arg.Op))
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatUint(arg.Value, 10))
		builder.WriteByte(':')
		builder.WriteString(strconv.FormatUint(arg.ValueTwo, 10))
		builder.WriteByte(';')
	}

	return builder.String()
}

func groupArgsByIndex(
	args []specs.LinuxSeccompArg,
) map[uint][]specs.LinuxSeccompArg {
	grouped := make(map[uint][]specs.LinuxSeccompArg)

	for _, arg := range args {
		grouped[arg.Index] = append(grouped[arg.Index], arg)
	}

	for idx := range grouped {
		sortArgs(grouped[idx])
	}

	return grouped
}

// conjoinArgs returns a single filter matching exactly the calls matched by
// both inputs. OCI argument filters are AND-joined and a runtime accepts at
// most one condition per argument index, so the conjunction exists only when
// every index present on both sides carries an identical condition. The
// second return value is false when no such filter exists.
func conjoinArgs(
	left, right []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	leftByIndex := groupArgsByIndex(left)
	rightByIndex := groupArgsByIndex(right)

	result := make([]specs.LinuxSeccompArg, 0, len(left)+len(right))

	for idx, leftGroup := range leftByIndex {
		if rightGroup, ok := rightByIndex[idx]; ok && !slices.Equal(leftGroup, rightGroup) {
			return nil, false
		}

		result = append(result, leftGroup...)
	}

	for idx, rightGroup := range rightByIndex {
		if _, ok := leftByIndex[idx]; !ok {
			result = append(result, rightGroup...)
		}
	}

	sortArgs(result)

	return result, true
}

// argsSubset reports whether every condition of sub also appears in super,
// which implies that super matches only calls that sub matches.
func argsSubset(sub, super []specs.LinuxSeccompArg) bool {
	for _, arg := range sub {
		if !slices.Contains(super, arg) {
			return false
		}
	}

	return true
}

// argsDisjoint reports whether two filters provably never match the same
// call. It is conservative: false means the filters may overlap.
func argsDisjoint(left, right []specs.LinuxSeccompArg) bool {
	for _, leftArg := range left {
		for _, rightArg := range right {
			if leftArg.Index == rightArg.Index && condsDisjoint(leftArg, rightArg) {
				return true
			}
		}
	}

	return false
}

// condsDisjoint reports whether two conditions on the same argument can never
// both hold.
func condsDisjoint(left, right specs.LinuxSeccompArg) bool {
	if left.Op == specs.OpEqualTo {
		return !condHolds(right, left.Value)
	}

	if right.Op == specs.OpEqualTo {
		return !condHolds(left, right.Value)
	}

	leftLo, leftHi, leftOk := condInterval(left)
	rightLo, rightHi, rightOk := condInterval(right)

	if !leftOk || !rightOk {
		return false
	}

	return leftHi < rightLo || rightHi < leftLo
}

// condInterval returns the inclusive value range (low, high) matched by a
// comparison operator. The third result is false for operators that do not
// describe a contiguous range, or for ranges that are empty.
func condInterval(arg specs.LinuxSeccompArg) (uint64, uint64, bool) {
	switch arg.Op {
	case specs.OpLessThan:
		if arg.Value == 0 {
			return 0, 0, false
		}

		return 0, arg.Value - 1, true
	case specs.OpLessEqual:
		return 0, arg.Value, true
	case specs.OpGreaterThan:
		if arg.Value == math.MaxUint64 {
			return 0, 0, false
		}

		return arg.Value + 1, math.MaxUint64, true
	case specs.OpGreaterEqual:
		return arg.Value, math.MaxUint64, true
	case specs.OpEqualTo:
		return arg.Value, arg.Value, true
	case specs.OpNotEqual, specs.OpMaskedEqual:
		return 0, 0, false
	default:
		return 0, 0, false
	}
}

// condHolds evaluates a single argument condition against a concrete value.
// Unknown operators never hold.
func condHolds(arg specs.LinuxSeccompArg, value uint64) bool {
	switch arg.Op {
	case specs.OpNotEqual:
		return value != arg.Value
	case specs.OpLessThan:
		return value < arg.Value
	case specs.OpLessEqual:
		return value <= arg.Value
	case specs.OpEqualTo:
		return value == arg.Value
	case specs.OpGreaterEqual:
		return value >= arg.Value
	case specs.OpGreaterThan:
		return value > arg.Value
	case specs.OpMaskedEqual:
		return value&arg.Value == arg.ValueTwo
	default:
		return false
	}
}
