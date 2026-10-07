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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

const otherNamespace = "other-ns"

// legacyEpoch is the creation time of the first object in the legacy tests.
var legacyEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func createdAt(minutes int) metav1.Time {
	return metav1.NewTime(legacyEpoch.Add(time.Duration(minutes) * time.Minute))
}

// legacyRecording is a recording created at the given minute.
func legacyRecording(
	namespace string,
	minute int,
	deleted bool,
) *profilerecordingapi.ProfileRecording {
	r := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, deleted)
	r.Namespace = namespace
	r.CreationTimestamp = createdAt(minute)

	return r
}

// legacyPartial is a partial profile recorded before 1.0, which only carries
// the recording name, created at the given minute.
func legacyPartial(name string, minute int, syscalls ...string) *seccompprofile.SeccompProfile {
	prf := partialSeccomp(name, "nginx", syscalls...)
	delete(prf.Labels, profilerecordingapi.ProfileToRecordingNamespaceLabel)
	prf.CreationTimestamp = createdAt(minute)

	return prf
}

// legacyMerged is a profile merged before 1.0: it carries the recording name
// but is not partial.
func legacyMerged(name string, minute int) *seccompprofile.SeccompProfile {
	prf := legacyPartial(name, minute, "read")
	delete(prf.Labels, profilebase.ProfilePartialLabel)

	return prf
}

func startLegacyAdopter(t *testing.T, r *PolicyMergeReconciler) {
	t.Helper()

	r.legacyAdoptionPending.Store(true)
	require.NoError(t, (&legacyAdopter{r: r}).Start(t.Context()))
	require.False(t, r.legacyAdoptionPending.Load())
}

func recordingNamespaceOf(t *testing.T, r *PolicyMergeReconciler, name string) string {
	t.Helper()

	prf := &seccompprofile.SeccompProfile{}
	require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: name}, prf))

	return prf.GetLabels()[profilerecordingapi.ProfileToRecordingNamespaceLabel]
}

func reconcileRecording(t *testing.T, r *PolicyMergeReconciler) reconcile.Result {
	t.Helper()

	res, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: testRecording, Namespace: testNamespace},
	})
	require.NoError(t, err)

	return res
}

func requireEvent(t *testing.T, r *PolicyMergeReconciler, reason string) {
	t.Helper()

	rec, ok := r.record.(*events.FakeRecorder)
	require.True(t, ok)

	for len(rec.Events) > 0 {
		if strings.Contains(<-rec.Events, reason) {
			return
		}
	}

	require.Failf(t, "missing event", "expected a %s event", reason)
}

func TestLegacyPartialProfileSelector(t *testing.T) {
	t.Parallel()

	r := newMergeReconciler(t,
		legacyPartial("legacy", 1, "read"),
		legacyMerged("legacy-merged", 1),
		partialSeccomp("namespaced", "nginx", "read"),
	)

	profiles, err := listLegacyPartialProfiles(t.Context(), r.client, testRecording)
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	require.Equal(t, "legacy", profiles[0].GetName())
}

// The adoption at startup labels each partial profile recorded before 1.0
// with the namespace of the only recording which may have recorded it.
func TestLegacyAdopter(t *testing.T) {
	t.Parallel()

	t.Run("a single recording which may own them adopts them", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyRecording(testNamespace, 0, false),
			legacyPartial("partial-a", 1, "read"),
			legacyPartial("partial-b", 1, "write"),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, testNamespace, recordingNamespaceOf(t, r, "partial-a"))
		require.Equal(t, testNamespace, recordingNamespaceOf(t, r, "partial-b"))
	})

	t.Run("a profile merged before 1.0 is not adopted", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyRecording(testNamespace, 0, false),
			legacyMerged("merged", 1),
		)

		startLegacyAdopter(t, r)

		// Recordings with this name in any namespace may still merge into it.
		require.Empty(t, recordingNamespaceOf(t, r, "merged"))
	})

	t.Run("a recording created after the profiles does not adopt them", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyPartial("stale", 0, "read"),
			legacyRecording(testNamespace, 1, false),
		)

		startLegacyAdopter(t, r)

		require.Empty(t, recordingNamespaceOf(t, r, "stale"))
	})

	t.Run("the creation time tells which recording recorded them", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyRecording(otherNamespace, 0, false),
			legacyPartial("partial", 1, "read"),
			legacyRecording(testNamespace, 2, false),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, otherNamespace, recordingNamespaceOf(t, r, "partial"))
	})

	t.Run("profiles which may belong to several recordings are not adopted", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyRecording(testNamespace, 0, false),
			legacyRecording(otherNamespace, 0, false),
			legacyPartial("partial", 1, "read"),
		)

		startLegacyAdopter(t, r)

		require.Empty(t, recordingNamespaceOf(t, r, "partial"))
		requireEvent(t, r, reasonAmbiguousLegacy)
	})

	t.Run("recordings outside of the cache are counted", func(t *testing.T) {
		t.Parallel()

		partial := legacyPartial("partial", 1, "read")
		own := legacyRecording(testNamespace, 0, false)

		// The cache only covers the watched namespace, the API server shows
		// the recording with the same name in another namespace too.
		r := newMergeReconciler(t, own, partial)
		r.reader = fake.NewClientBuilder().
			WithScheme(mergerTestScheme(t)).
			WithObjects(own.DeepCopy(), legacyRecording(otherNamespace, 0, false), partial.DeepCopy()).
			Build()

		startLegacyAdopter(t, r)

		require.Empty(t, recordingNamespaceOf(t, r, "partial"))
	})
}

// A deleted recording waits for the adoption at startup, and is held as long
// as partial profiles recorded before 1.0 exist which it may own.
func TestLegacyHold(t *testing.T) {
	t.Parallel()

	t.Run("a deleted recording waits for the adoption at startup", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyRecording(testNamespace, 0, true),
			partialSeccomp("partial", "nginx", "read"),
		)
		r.legacyAdoptionPending.Store(true)

		require.Equal(t, reconcile.Result{RequeueAfter: legacyAdoptionWait},
			reconcileRecording(t, r))

		// Nothing is merged yet.
		require.NoError(t, r.client.Get(t.Context(), types.NamespacedName{Name: "partial"},
			&seccompprofile.SeccompProfile{}))
	})

	t.Run("adopted profiles are merged when their recording is deleted", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyRecording(testNamespace, 0, true),
			legacyPartial("partial-a", 1, "read"),
			legacyPartial("partial-b", 1, "write"),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, reconcile.Result{}, reconcileRecording(t, r))
		require.ElementsMatch(t, []string{"read", "write"}, mergedSyscalls(t, r, "nginx"))
		requireRecordingReleased(t, r)
	})

	t.Run("a recording created after stale profiles is not held", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t,
			legacyPartial("stale", 0, "read"),
			legacyRecording(testNamespace, 1, true),
		)

		startLegacyAdopter(t, r)

		require.Equal(t, reconcile.Result{}, reconcileRecording(t, r))
		requireRecordingReleased(t, r)

		// The stale profile is neither adopted nor merged.
		require.Empty(t, recordingNamespaceOf(t, r, "stale"))
	})

	t.Run(
		"profiles which may belong to several recordings hold them until labeled",
		func(t *testing.T) {
			t.Parallel()

			r := newMergeReconciler(t,
				legacyRecording(testNamespace, 0, true),
				legacyRecording(otherNamespace, 0, false),
				legacyPartial("partial", 1, "read"),
			)

			startLegacyAdopter(t, r)

			// Releasing the recording would orphan the profile, merging it could
			// merge the syscalls of the other recording.
			require.Equal(t, reconcile.Result{RequeueAfter: legacyHoldWait},
				reconcileRecording(t, r))
			requireEvent(t, r, reasonHeldForLegacy)
			requireRecordingHeld(t, r)
			require.Empty(t, recordingNamespaceOf(t, r, "partial"))

			// Once the profile is attributed, it is merged like any other.
			prf := &seccompprofile.SeccompProfile{}
			require.NoError(
				t,
				r.client.Get(t.Context(), types.NamespacedName{Name: "partial"}, prf),
			)
			prf.Labels[profilerecordingapi.ProfileToRecordingNamespaceLabel] = testNamespace
			require.NoError(t, r.client.Update(t.Context(), prf))

			require.Equal(t, reconcile.Result{}, reconcileRecording(t, r))
			require.ElementsMatch(t, []string{"read"}, mergedSyscalls(t, r, "nginx"))
			requireRecordingReleased(t, r)
		},
	)
}

func requireRecordingHeld(t *testing.T, r *PolicyMergeReconciler) {
	t.Helper()

	recording := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, r.client.Get(t.Context(),
		types.NamespacedName{Name: testRecording, Namespace: testNamespace}, recording))
	require.Contains(t, recording.GetFinalizers(), profilerecordingapi.RecordingHasUnmergedProfiles)
}

// requireRecordingReleased checks that the finalizer is gone, which deletes
// the recording.
func requireRecordingReleased(t *testing.T, r *PolicyMergeReconciler) {
	t.Helper()

	recording := &profilerecordingapi.ProfileRecording{}

	err := r.client.Get(t.Context(),
		types.NamespacedName{Name: testRecording, Namespace: testNamespace}, recording)
	if kerrors.IsNotFound(err) {
		return
	}

	require.NoError(t, err)
	require.NotContains(
		t,
		recording.GetFinalizers(),
		profilerecordingapi.RecordingHasUnmergedProfiles,
	)
}
