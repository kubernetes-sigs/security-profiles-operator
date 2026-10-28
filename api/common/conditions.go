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

// +kubebuilder:object:generate=true
package common

import (
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A ConditionType represents a condition a resource could be in.
type ConditionType string

// Condition types.
const (
	// TypeReady resources are believed to be ready to handle work.
	TypeReady ConditionType = "Ready"
)

// A ConditionReason represents the reason a resource is in a condition.
type ConditionReason string

// Reasons a resource is or is not ready.
const (
	ReasonAvailable   ConditionReason = "Available"
	ReasonUnavailable ConditionReason = "Unavailable"
	ReasonCreating    ConditionReason = "Creating"
	ReasonDeleting    ConditionReason = "Deleting"
	ReasonPending     ConditionReason = "Pending"
	ReasonUpdating    ConditionReason = "Updating"
)

// A ConditionedStatus reflects the observed status of a resource. Only one
// condition of each type may exist.
type ConditionedStatus struct {
	// conditions contains the conditions of the resource.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"` //nolint:lll,tagalign // required struct tags
}

// GetReadyCondition returns the condition for the given ConditionType if exists,
// otherwise returns an unknown condition.
func (s *ConditionedStatus) GetReadyCondition() metav1.Condition {
	if c := meta.FindStatusCondition(s.Conditions, string(TypeReady)); c != nil {
		return *c
	}

	return metav1.Condition{
		Type:   string(TypeReady),
		Status: metav1.ConditionUnknown,
	}
}

// SetConditions sets the supplied conditions, replacing any existing conditions
// of the same type. This is a no-op if all supplied conditions are identical,
// ignoring the last transition time, to those already set. The last transition
// time of a condition only changes with its status, a condition without one
// gets the current time.
func (s *ConditionedStatus) SetConditions(c ...metav1.Condition) {
	for _, cond := range c {
		if existing := meta.FindStatusCondition(s.Conditions, cond.Type); existing != nil &&
			conditionsEqual(existing, &cond) {
			continue
		}

		meta.SetStatusCondition(&s.Conditions, cond)
	}
}

// Equal returns true if the status is identical to the supplied status,
// ignoring the LastTransitionTimes and order of statuses.
func (s *ConditionedStatus) Equal(other *ConditionedStatus) bool {
	if s == nil || other == nil {
		return s == nil && other == nil
	}

	if len(other.Conditions) != len(s.Conditions) {
		return false
	}

	byType := func(a, b metav1.Condition) int { return strings.Compare(a.Type, b.Type) }

	// We should not have more than one condition of each type.
	sc := slices.SortedFunc(slices.Values(s.Conditions), byType)
	oc := slices.SortedFunc(slices.Values(other.Conditions), byType)

	for i := range sc {
		if !conditionsEqual(&sc[i], &oc[i]) {
			return false
		}
	}

	return true
}

func conditionsEqual(a, b *metav1.Condition) bool {
	return a.Type == b.Type &&
		a.Status == b.Status &&
		a.Reason == b.Reason &&
		a.Message == b.Message
}

// Creating returns a condition that indicates the resource is currently
// being created.
func Creating(message ...string) metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonCreating),
		Message:            firstOr(message),
	}
}

// Deleting returns a condition that indicates the resource is currently
// being deleted.
func Deleting(message ...string) metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonDeleting),
		Message:            firstOr(message),
	}
}

// Available returns a condition that indicates the resource is
// currently observed to be available for use.
func Available(message ...string) metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonAvailable),
		Message:            firstOr(message),
	}
}

// Unavailable returns a condition that indicates the resource is not
// currently available for use.
func Unavailable(message ...string) metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonUnavailable),
		Message:            firstOr(message),
	}
}

// Pending returns a condition that indicates the resource is currently
// observed to be waiting for creating.
func Pending(message ...string) metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonPending),
		Message:            firstOr(message),
	}
}

// Updating returns a condition that indicates the resource is currently
// observed to be updating.
func Updating(message ...string) metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonUpdating),
		Message:            firstOr(message),
	}
}

func firstOr(values []string) string {
	if len(values) > 0 {
		return values[0]
	}

	return ""
}
