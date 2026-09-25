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
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

const (
	testRecording = "test-recording"
	testNamespace = "test-ns"
)

func testMergeRecording(
	kind profilerecordingapi.ProfileRecordingKind,
	deleted bool,
) *profilerecordingapi.ProfileRecording {
	r := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testRecording,
			Namespace:  testNamespace,
			Finalizers: []string{profilerecordingapi.RecordingHasUnmergedProfiles},
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:          kind,
			MergeStrategy: profilerecordingapi.ProfileMergeContainers,
		},
	}

	if deleted {
		now := metav1.NewTime(time.Now())
		r.DeletionTimestamp = &now
	}

	return r
}

// Profiles are cluster-scoped (+kubebuilder:resource:scope=Cluster), so the
// recording namespace only ever appears as a label on them.
func partialSeccomp(name, container string, syscalls ...string) *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel:          testRecording,
				profilerecordingapi.ProfileToRecordingNamespaceLabel: testNamespace,
				profilerecordingapi.ProfileToContainerLabel:          container,
				profilebase.ProfilePartialLabel:                      "true",
			},
		},
		Spec: seccompprofile.SeccompProfileSpec{
			DefaultAction: seccompprofile.ActErrno,
			Syscalls: []seccompprofile.Syscall{{
				Action: seccompprofile.ActAllow,
				Names:  syscalls,
			}},
		},
	}
}

// mergerTestScheme extends the profile scheme with ProfileRecording, which the
// reconciler reads but the profile-only coverage scheme does not register.
func mergerTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := coverageTestScheme(t)
	require.NoError(t, profilerecordingapi.AddToScheme(scheme))

	return scheme
}

func newMergeReconciler(t *testing.T, objs ...client.Object) *PolicyMergeReconciler {
	t.Helper()

	return &PolicyMergeReconciler{
		client: fake.NewClientBuilder().
			WithScheme(mergerTestScheme(t)).
			WithObjects(objs...).
			Build(),
		log:    logr.Discard(),
		record: events.NewFakeRecorder(20),
	}
}

// Reconcile only acts on a recording that is being deleted; anything else is a
// no-op. This is the entry point the controller predicate feeds.
func TestReconcile(t *testing.T) {
	t.Parallel()

	t.Run("a live recording is ignored", func(t *testing.T) {
		t.Parallel()

		recording := testMergeRecording(
			profilerecordingapi.ProfileRecordingKindSeccompProfile, false)
		partial := partialSeccomp("partial-a", "nginx", "read")
		r := newMergeReconciler(t, recording, partial)

		res, err := r.Reconcile(t.Context(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: testRecording, Namespace: testNamespace,
			},
		})
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res)

		// Nothing merged: the partial profile is untouched.
		got := &seccompprofile.SeccompProfile{}
		require.NoError(t, r.client.Get(t.Context(),
			types.NamespacedName{Name: "partial-a"}, got))
	})

	t.Run("a missing recording is not an error", func(t *testing.T) {
		t.Parallel()

		r := newMergeReconciler(t)

		res, err := r.Reconcile(t.Context(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "gone", Namespace: testNamespace,
			},
		})
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res)
	})

	t.Run("a deleted recording merges its partial profiles", func(t *testing.T) {
		t.Parallel()

		recording := testMergeRecording(
			profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
		r := newMergeReconciler(t,
			recording,
			partialSeccomp("partial-a", "nginx", "read"),
			partialSeccomp("partial-b", "nginx", "write"),
		)

		_, err := r.Reconcile(t.Context(), reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: testRecording, Namespace: testNamespace,
			},
		})
		require.NoError(t, err)

		merged := &seccompprofile.SeccompProfile{}
		require.NoError(t, r.client.Get(t.Context(),
			types.NamespacedName{Name: testRecording + "-nginx"}, merged))

		var names []string
		for _, s := range merged.Spec.Syscalls {
			names = append(names, s.Names...)
		}

		require.ElementsMatch(t, []string{"read", "write"}, names)

		// The partial profiles are cleaned up so the finalizer can be released.
		list := &seccompprofile.SeccompProfileList{}
		require.NoError(t, r.client.List(t.Context(), list))

		for i := range list.Items {
			require.NotContains(t, list.Items[i].GetLabels(), profilebase.ProfilePartialLabel)
		}
	})
}

func mergedSyscalls(t *testing.T, r *PolicyMergeReconciler, container string) []string {
	t.Helper()

	merged := &seccompprofile.SeccompProfile{}
	require.NoError(t, r.client.Get(t.Context(),
		types.NamespacedName{Name: testRecording + "-" + container}, merged))

	var names []string
	for _, s := range merged.Spec.Syscalls {
		names = append(names, s.Names...)
	}

	return names
}

// Partial profiles get deleted after each merge, so a later merge round has to
// keep the result of the earlier ones.
func TestMergeProfilesKeepsExistingMergedProfile(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	r := newMergeReconciler(t, recording, partialSeccomp("partial-a", "redis", "read"))

	require.NoError(t, r.mergeProfiles(t.Context(), recording))
	require.ElementsMatch(t, []string{"read"}, mergedSyscalls(t, r, "redis"))

	require.NoError(t, r.client.Create(t.Context(), partialSeccomp("partial-b", "redis", "write")))
	require.NoError(t, r.mergeProfiles(t.Context(), recording))
	require.ElementsMatch(t, []string{"read", "write"}, mergedSyscalls(t, r, "redis"))
}

// Only a merged profile created by this recording gets merged into the result,
// others, like the one of a deleted recording with the same name, get replaced.
func TestMergeProfilesReplacesUnrelatedMergedProfile(t *testing.T) {
	t.Parallel()

	for name, modify := range map[string]func(*seccompprofile.SeccompProfile){
		"created before the recording": func(p *seccompprofile.SeccompProfile) {
			p.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
		},
		"without recording labels": func(p *seccompprofile.SeccompProfile) {
			p.Labels = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recording := testMergeRecording(
				profilerecordingapi.ProfileRecordingKindSeccompProfile,
				true,
			)
			recording.CreationTimestamp = metav1.NewTime(time.Now())

			existing := partialSeccomp(testRecording+"-redis", "redis", "exec")
			delete(existing.Labels, profilebase.ProfilePartialLabel)
			existing.CreationTimestamp = metav1.NewTime(time.Now().Add(time.Hour))
			modify(existing)

			r := newMergeReconciler(
				t,
				recording,
				existing,
				partialSeccomp("partial-a", "redis", "read"),
			)

			require.NoError(t, r.mergeProfiles(t.Context(), recording))
			require.ElementsMatch(t, []string{"read"}, mergedSyscalls(t, r, "redis"))
		})
	}
}

// Profiles are cluster scoped, so a same named recording in another namespace
// must not overwrite the merged profile of this one.
func TestMergeProfilesSkipsProfileOfOtherRecording(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)

	other := partialSeccomp(testRecording+"-nginx", "nginx", "exec")
	other.Labels[profilerecordingapi.ProfileToRecordingNamespaceLabel] = "other-ns"
	delete(other.Labels, profilebase.ProfilePartialLabel)

	r := newMergeReconciler(t, recording, other, partialSeccomp("partial-a", "nginx", "read"))

	require.NoError(t, r.mergeProfiles(t.Context(), recording))
	require.ElementsMatch(t, []string{"exec"}, mergedSyscalls(t, r, "nginx"))
}

// mergeProfiles dispatches on the recording kind; an unknown kind has to be
// reported rather than silently doing nothing.
func TestMergeProfilesUnknownKind(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording("NotAKind", true)
	r := newMergeReconciler(t, recording)

	err := r.mergeProfiles(t.Context(), recording)
	require.ErrorContains(t, err, "cannot merge profiles")
}

// A container whose partial profiles merge to nothing must not abort the whole
// recording: the remaining containers still need merging and the partial
// profiles still need deleting, otherwise the finalizer is never released.

// The AppArmor and SELinux dispatchers take the same path as seccomp; exercise
// them so a wrong list type or label selector cannot go unnoticed.
func TestMergeProfilesPerKind(t *testing.T) {
	t.Parallel()

	t.Run("apparmor with no partial profiles", func(t *testing.T) {
		t.Parallel()

		recording := testMergeRecording(
			profilerecordingapi.ProfileRecordingKindAppArmorProfile, true)
		r := newMergeReconciler(t, recording)

		require.NoError(t, r.mergeProfiles(t.Context(), recording))

		list := &apparmorprofileapi.AppArmorProfileList{}
		require.NoError(t, r.client.List(t.Context(), list))
		require.Empty(t, list.Items)
	})

	t.Run("selinux with no partial profiles", func(t *testing.T) {
		t.Parallel()

		recording := testMergeRecording(
			profilerecordingapi.ProfileRecordingKindSelinuxProfile, true)
		r := newMergeReconciler(t, recording)

		require.NoError(t, r.mergeProfiles(t.Context(), recording))
	})
}

// A partial profile created after the listing, for example by another pod of
// the recording, must survive the cleanup so that the next merge includes it.
func TestDeletePartialProfilesOnlyDeletesListed(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	r := newMergeReconciler(t, recording,
		partialSeccomp("first", "ctr", "read"),
		partialSeccomp("unlabeled", "", "write"),
	)

	_, listed, err := listPartialProfiles(
		t.Context(), r.client, &seccompprofile.SeccompProfileList{}, recording,
	)
	require.NoError(t, err)
	require.Len(t, listed, 2, "partial profiles without container are cleaned up as well")

	require.NoError(t, r.client.Create(t.Context(), partialSeccomp("late", "ctr", "open")))
	require.NoError(t, deletePartialProfiles(t.Context(), r.client, listed))

	list := &seccompprofile.SeccompProfileList{}
	require.NoError(t, r.client.List(t.Context(), list))
	require.Len(t, list.Items, 1)
	require.Equal(t, "late", list.Items[0].Name)

	// A profile which is already gone is not an error.
	require.NoError(t, deletePartialProfiles(t.Context(), r.client, listed))
}
