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

package recordingmerger

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// syscallCoverageAnnotation is set on a merged SeccompProfile (mergeStrategy=
// Containers) recording, per syscall, how many collected partials contained it.
// Informational only; never affects the enforced profile.
const syscallCoverageAnnotation = "spo.x-k8s.io/syscall-coverage"

// syscallCoveragePartialsAnnotation is set next to syscallCoverageAnnotation
// and holds the comma separated UIDs of the partial profiles of the last
// merge, which the coverage counts already. Merging the same partial profiles
// again, because deleting them failed after the merged profile got written,
// then does not count them twice. Only the partial profiles of the last merge
// are kept, the earlier ones are gone already, so the list does not grow.
const syscallCoveragePartialsAnnotation = "spo.x-k8s.io/syscall-coverage-partials"

// syscallCoverageSchemaVersion is the annotation value's schema version.
const syscallCoverageSchemaVersion = "v1"

// syscallCoverage is the JSON document stored in syscallCoverageAnnotation:
// Total merged partials, and per syscall how many of them contained it.
type syscallCoverage struct {
	Version  string         `json:"version"`
	Total    int            `json:"total"`
	Syscalls map[string]int `json:"syscalls"`
}

// partialCoverage holds the syscalls of a partial seccomp profile. They are
// collected before the merge, which changes the first partial profile.
type partialCoverage struct {
	uid      types.UID
	syscalls []string
}

// seccompPartialCoverage returns the syscalls of each partial profile, or
// nil if they are not all seccomp profiles.
func seccompPartialCoverage(partials []mergeableProfile) []partialCoverage {
	coverage := make([]partialCoverage, 0, len(partials))

	for _, partial := range partials {
		seccompPartial, ok := partial.(*mergeableSeccompProfile)
		if !ok {
			// mergeTypedProfiles groups profiles by type before calling this
			// function, so mixed profile types are not expected. Coverage is
			// informational and must not prevent profile merging, so safely omit
			// the annotation rather than returning an error.
			return nil
		}

		seen := make(map[string]struct{})

		for i := range seccompPartial.Spec.Syscalls {
			for _, name := range seccompPartial.Spec.Syscalls[i].Names {
				seen[name] = struct{}{}
			}
		}

		syscalls := make([]string, 0, len(seen))
		for name := range seen {
			syscalls = append(syscalls, name)
		}

		coverage = append(coverage, partialCoverage{
			uid: seccompPartial.GetUID(), syscalls: syscalls,
		})
	}

	return coverage
}

func seccompCoverageAnnotation(partials []mergeableProfile) (string, error) {
	return coverageAnnotation(seccompPartialCoverage(partials))
}

// coverageAnnotation returns the value of syscallCoverageAnnotation for the
// partial profiles, empty if there are none.
func coverageAnnotation(partials []partialCoverage) (string, error) {
	if len(partials) == 0 {
		return "", nil
	}

	counts := make(map[string]int)

	for _, partial := range partials {
		for _, name := range partial.syscalls {
			counts[name]++
		}
	}

	coverage := syscallCoverage{
		Version:  syscallCoverageSchemaVersion,
		Total:    len(partials),
		Syscalls: counts,
	}

	data, err := json.Marshal(coverage)
	if err != nil {
		return "", fmt.Errorf("marshal syscall coverage: %w", err)
	}

	return string(data), nil
}

// mergedCoverage returns the values of syscallCoverageAnnotation and
// syscallCoveragePartialsAnnotation for a merge of the partial profiles into
// the merged profile with the provided annotations. If the merge keeps the
// existing profile, the coverage adds up, without the partial profiles which
// the existing coverage counts already. An empty coverage leaves the
// annotation as it is.
func mergedCoverage(
	partials []partialCoverage, annotations map[string]string, kept bool,
) (coverage, counted string) {
	uncounted := partials

	if kept {
		previous := strings.Split(annotations[syscallCoveragePartialsAnnotation], ",")
		uncounted = slices.DeleteFunc(slices.Clone(partials), func(p partialCoverage) bool {
			return p.uid != "" && slices.Contains(previous, string(p.uid))
		})
	}

	// The coverage schema contains only JSON-supported types, so an error
	// is theoretical. The coverage is informational and must not prevent the
	// merge, so the annotation stays as it is then.
	coverage, err := coverageAnnotation(uncounted)
	if err != nil {
		coverage = ""
	}

	if kept {
		coverage = addSyscallCoverage(annotations[syscallCoverageAnnotation], coverage)
	}

	uids := make([]string, 0, len(partials))

	for _, p := range partials {
		if p.uid != "" {
			uids = append(uids, string(p.uid))
		}
	}

	slices.Sort(uids)

	return coverage, strings.Join(slices.Compact(uids), ",")
}

// addSyscallCoverage returns the coverage of the partial profiles of both
// annotation values, for a merge into a profile which holds the syscalls of
// earlier merges. A previous value which is missing or cannot be read, for
// example because a version before the annotation existed merged the
// profile, adds nothing. Without a current value, which computing it never
// fails to return for seccomp profiles, nothing is returned and the
// annotation stays as it is.
func addSyscallCoverage(previous, current string) string {
	if previous == "" || current == "" {
		return current
	}

	var prev, cur syscallCoverage
	if err := json.Unmarshal([]byte(previous), &prev); err != nil ||
		prev.Version != syscallCoverageSchemaVersion {
		return current
	}

	if err := json.Unmarshal([]byte(current), &cur); err != nil {
		return current
	}

	if cur.Syscalls == nil {
		cur.Syscalls = map[string]int{}
	}

	cur.Total += prev.Total

	for name, count := range prev.Syscalls {
		cur.Syscalls[name] += count
	}

	data, err := json.Marshal(cur)
	if err != nil {
		return current
	}

	return string(data)
}

func setSyscallCoverageAnnotation(obj metav1.Object, value string) {
	setAnnotation(obj, syscallCoverageAnnotation, value)
}

// setAnnotation sets the annotation on the object, unless the value is empty.
func setAnnotation(obj metav1.Object, key, value string) {
	if value == "" {
		return
	}

	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	annotations[key] = value
	obj.SetAnnotations(annotations)
}
