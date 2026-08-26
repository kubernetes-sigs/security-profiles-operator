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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// syscallCoverageAnnotation is set on a merged SeccompProfile (mergeStrategy=
// Containers) recording, per syscall, how many collected partials contained it.
// Informational only; never affects the enforced profile.
const syscallCoverageAnnotation = "spo.x-k8s.io/syscall-coverage"

// syscallCoverageSchemaVersion is the annotation value's schema version.
const syscallCoverageSchemaVersion = "v1"

// syscallCoverage is the JSON document stored in syscallCoverageAnnotation:
// Total merged partials, and per syscall how many of them contained it.
type syscallCoverage struct {
	Version  string         `json:"version"`
	Total    int            `json:"total"`
	Syscalls map[string]int `json:"syscalls"`
}

func seccompCoverageAnnotation(partials []mergeableProfile) (string, error) {
	if len(partials) == 0 {
		return "", nil
	}

	counts := make(map[string]int)

	for _, partial := range partials {
		seccompPartial, ok := partial.(*mergeableSeccompProfile)
		if !ok {
			// mergeTypedProfiles groups profiles by type before calling this
			// function, so mixed profile types are not expected. Coverage is
			// informational and must not prevent profile merging, so safely omit
			// the annotation rather than returning an error.
			return "", nil
		}

		seen := make(map[string]struct{})

		for i := range seccompPartial.Spec.Syscalls {
			for _, name := range seccompPartial.Spec.Syscalls[i].Names {
				seen[name] = struct{}{}
			}
		}

		for name := range seen {
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

func setSyscallCoverageAnnotation(obj metav1.Object, value string) {
	if value == "" {
		return
	}

	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	annotations[syscallCoverageAnnotation] = value
	obj.SetAnnotations(annotations)
}
