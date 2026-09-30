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
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConditionConstructors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		fn     func(...string) metav1.Condition
		status metav1.ConditionStatus
		reason ConditionReason
	}{
		{name: "creating", fn: Creating, status: metav1.ConditionFalse, reason: ReasonCreating},
		{name: "deleting", fn: Deleting, status: metav1.ConditionFalse, reason: ReasonDeleting},
		{name: "available", fn: Available, status: metav1.ConditionTrue, reason: ReasonAvailable},
		{name: "unavailable", fn: Unavailable, status: metav1.ConditionFalse, reason: ReasonUnavailable},
		{name: "pending", fn: Pending, status: metav1.ConditionFalse, reason: ReasonPending},
		{name: "updating", fn: Updating, status: metav1.ConditionFalse, reason: ReasonUpdating},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := tc.fn()
			require.Equal(t, string(TypeReady), c.Type)
			require.Equal(t, tc.status, c.Status)
			require.Equal(t, string(tc.reason), c.Reason)
			require.Empty(t, c.Message)
			require.False(t, c.LastTransitionTime.IsZero())

			// Only the first message is used.
			c = tc.fn("first", "second")
			require.Equal(t, "first", c.Message)
		})
	}
}

func TestGetReadyCondition(t *testing.T) {
	t.Parallel()

	status := &ConditionedStatus{}
	require.Equal(t, metav1.Condition{
		Type:   string(TypeReady),
		Status: metav1.ConditionUnknown,
	}, status.GetReadyCondition())

	status.Conditions = []metav1.Condition{
		{Type: "Other", Status: metav1.ConditionTrue},
		Available("ready"),
	}
	ready := status.GetReadyCondition()
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	require.Equal(t, "ready", ready.Message)
}

func TestSetConditions(t *testing.T) {
	t.Parallel()

	t.Run("appends a new type", func(t *testing.T) {
		t.Parallel()

		status := &ConditionedStatus{}
		status.SetConditions(Creating())
		status.SetConditions(metav1.Condition{Type: "Other", Status: metav1.ConditionTrue})

		require.Len(t, status.Conditions, 2)
	})

	t.Run("replaces a changed condition of the same type", func(t *testing.T) {
		t.Parallel()

		status := &ConditionedStatus{}
		status.SetConditions(Creating())
		status.SetConditions(Available("done"))

		require.Len(t, status.Conditions, 1)
		require.Equal(t, string(ReasonAvailable), status.Conditions[0].Reason)
		require.Equal(t, "done", status.Conditions[0].Message)
	})

	t.Run("keeps the transition time of an identical condition", func(t *testing.T) {
		t.Parallel()

		old := Available("done")
		old.LastTransitionTime = metav1.Unix(1, 0)

		status := &ConditionedStatus{Conditions: []metav1.Condition{old}}
		status.SetConditions(Available("done"))

		require.Len(t, status.Conditions, 1)
		require.Equal(t, metav1.Unix(1, 0), status.Conditions[0].LastTransitionTime)
	})
}

func TestEqual(t *testing.T) {
	t.Parallel()

	a := &ConditionedStatus{Conditions: []metav1.Condition{
		Available("done"),
		{Type: "Other", Status: metav1.ConditionFalse, Reason: "Reason"},
	}}

	// The order and the transition times do not matter.
	b := &ConditionedStatus{Conditions: []metav1.Condition{
		{
			Type:               "Other",
			Status:             metav1.ConditionFalse,
			Reason:             "Reason",
			LastTransitionTime: metav1.Unix(1, 0),
		},
		Available("done"),
	}}

	require.True(t, a.Equal(b))
	require.True(t, b.Equal(a))

	var nilStatus *ConditionedStatus

	require.True(t, nilStatus.Equal(nil))
	require.False(t, a.Equal(nil))
	require.False(t, nilStatus.Equal(a))

	require.False(t, a.Equal(&ConditionedStatus{Conditions: []metav1.Condition{Available("done")}}))
	require.False(t, a.Equal(&ConditionedStatus{Conditions: []metav1.Condition{
		Available("other message"),
		{Type: "Other", Status: metav1.ConditionFalse, Reason: "Reason"},
	}}))

	// The copies are sorted, not the originals.
	require.Equal(t, string(TypeReady), a.Conditions[0].Type)
}

func TestSetConditionForGeneration(t *testing.T) {
	t.Parallel()

	status := &ConditionedStatus{}
	condition := Available("done")
	condition.LastTransitionTime = metav1.Unix(1, 0)

	status.SetConditionForGeneration(&condition, 1)
	require.Len(t, status.Conditions, 1)
	require.Equal(t, int64(1), status.Conditions[0].ObservedGeneration)

	// Only the generation changed, so the transition time stays.
	next := Available("done")
	status.SetConditionForGeneration(&next, 2)
	require.Len(t, status.Conditions, 1)
	require.Equal(t, int64(2), status.Conditions[0].ObservedGeneration)
	require.Equal(t, metav1.Unix(1, 0), status.Conditions[0].LastTransitionTime)

	// The passed condition is not modified.
	require.Zero(t, next.ObservedGeneration)
}
