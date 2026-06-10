/*
Copyright 2026 The Kubernetes Authors.

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
	"sort"

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
	for _, c := range s.Conditions {
		if c.Type == string(TypeReady) {
			return c
		}
	}

	return metav1.Condition{
		Type:   string(TypeReady),
		Status: metav1.ConditionUnknown,
	}
}

// SetConditions sets the supplied conditions, replacing any existing conditions
// of the same type. This is a no-op if all supplied conditions are identical,
// ignoring the last transition time, to those already set.
func (s *ConditionedStatus) SetConditions(c ...metav1.Condition) {
	for _, new := range c {
		exists := false

		for i, existing := range s.Conditions {
			if existing.Type != new.Type {
				continue
			}

			if conditionsEqual(&existing, &new) {
				exists = true

				continue
			}

			s.Conditions[i] = new
			exists = true
		}

		if !exists {
			s.Conditions = append(s.Conditions, new)
		}
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

	sc := make([]metav1.Condition, len(s.Conditions))
	copy(sc, s.Conditions)

	oc := make([]metav1.Condition, len(other.Conditions))
	copy(oc, other.Conditions)

	// We should not have more than one condition of each type.
	sort.Slice(sc, func(i, j int) bool { return sc[i].Type < sc[j].Type })
	sort.Slice(oc, func(i, j int) bool { return oc[i].Type < oc[j].Type })

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
func Creating() metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonCreating),
	}
}

// Deleting returns a condition that indicates the resource is currently
// being deleted.
func Deleting() metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonDeleting),
	}
}

// Available returns a condition that indicates the resource is
// currently observed to be available for use.
func Available() metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonAvailable),
	}
}

// Unavailable returns a condition that indicates the resource is not
// currently available for use.
func Unavailable() metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonUnavailable),
	}
}

// Pending returns a condition that indicates the resource is currently
// observed to be waiting for creating.
func Pending() metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonPending),
	}
}

// Updating returns a condition that indicates the resource is currently
// observed to be updating.
func Updating() metav1.Condition {
	return metav1.Condition{
		Type:               string(TypeReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             string(ReasonUpdating),
	}
}
