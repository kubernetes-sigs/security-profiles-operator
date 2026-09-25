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

package common

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetConditionForGeneration sets the condition and records the generation of
// the object it was observed for. SetConditions keeps an existing condition
// which only differs in its observed generation, so that its transition time
// stays, and the generation is updated separately.
func (s *ConditionedStatus) SetConditionForGeneration(c *metav1.Condition, generation int64) {
	condition := *c
	condition.ObservedGeneration = generation
	s.SetConditions(condition)

	for i := range s.Conditions {
		if s.Conditions[i].Type == c.Type {
			s.Conditions[i].ObservedGeneration = generation
		}
	}
}
