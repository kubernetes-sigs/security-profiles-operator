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
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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
			WithIndex(&profilerecordingapi.ProfileRecording{}, recordingNameKey, recordingNameIndex).
			Build(),
		log:    logr.Discard(),
		record: events.NewFakeRecorder(20),
	}
}

// requireMerged merges the partial profiles of the recording and returns the
// merged profiles which blocked the merge.
func requireMerged(
	t *testing.T, r *PolicyMergeReconciler, recording *profilerecordingapi.ProfileRecording,
) []string {
	t.Helper()

	blocked, err := r.mergeProfiles(t.Context(), recording)
	require.NoError(t, err)

	return blocked
}

// requireMergeError requires the merge of the partial profiles of the
// recording to fail with errMergeTest.
func requireMergeError(
	t *testing.T, r *PolicyMergeReconciler, recording *profilerecordingapi.ProfileRecording,
) {
	t.Helper()

	_, err := r.mergeProfiles(t.Context(), recording)
	require.ErrorIs(t, err, errMergeTest)
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

	requireMerged(t, r, recording)
	require.ElementsMatch(t, []string{"read"}, mergedSyscalls(t, r, "redis"))

	require.NoError(t, r.client.Create(t.Context(), partialSeccomp("partial-b", "redis", "write")))
	requireMerged(t, r, recording)
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

			requireMerged(t, r, recording)
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

	r := newMergeReconciler(t, recording, other,
		partialSeccomp("partial-a", "nginx", "read"),
		partialSeccomp("partial-b", "redis", "write"),
	)

	require.Equal(t, []string{testRecording + "-nginx"}, requireMerged(t, r, recording))
	require.ElementsMatch(t, []string{"exec"}, mergedSyscalls(t, r, "nginx"))
	require.ElementsMatch(t, []string{"write"}, mergedSyscalls(t, r, "redis"))

	// The recorded data of the skipped container is kept, while the partial
	// profiles of the merged container are cleaned up.
	require.NoError(t, r.client.Get(t.Context(),
		client.ObjectKey{Name: "partial-a"}, &seccompprofile.SeccompProfile{}))
	require.True(t, kerrors.IsNotFound(r.client.Get(t.Context(),
		client.ObjectKey{Name: "partial-b"}, &seccompprofile.SeccompProfile{})))

	// The kept partial profile keeps holding the recording.
	got := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, r.client.Get(t.Context(), client.ObjectKeyFromObject(recording), got))
	require.Contains(t, got.Finalizers, profilerecordingapi.RecordingHasUnmergedProfiles)
}

// A profile which was not recorded, for example one written by a cluster
// admin, must never be replaced by a recording with a matching name.
func TestMergeProfilesSkipsProfileWithoutRecordingLabels(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)

	foreign := partialSeccomp(testRecording+"-nginx", "nginx", "exec")
	foreign.Labels = nil

	r := newMergeReconciler(t, recording, foreign, partialSeccomp("partial-a", "nginx", "read"))

	require.Equal(t, []string{testRecording + "-nginx"}, requireMerged(t, r, recording))
	require.ElementsMatch(t, []string{"exec"}, mergedSyscalls(t, r, "nginx"))
}

// A deleted recording whose merge is blocked by a profile of somebody else is
// retried, and released once the profile is gone.
func TestReconcileRequeuesBlockedMerge(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)

	foreign := partialSeccomp(testRecording+"-nginx", "nginx", "exec")
	foreign.Labels = nil

	r := newMergeReconciler(t, recording, foreign, partialSeccomp("partial-a", "nginx", "read"))
	r.legacyAdoptionPending.Store(false)

	res, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(recording),
	})
	require.NoError(t, err)
	require.Equal(t, blockedRequeueMinDelay, res.RequeueAfter)
	requireEvent(t, r, reasonMergedProfileConflict)

	// The profile which blocks the merge enqueues the recording.
	require.Equal(t,
		[]reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(recording)}},
		r.recordingsBlockedBy(t.Context(), foreign))

	require.NoError(t, r.client.Delete(t.Context(), foreign))

	res, err = r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(recording),
	})
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.ElementsMatch(t, []string{"read"}, mergedSyscalls(t, r, "nginx"))

	// The fake client deletes the released recording, which was only kept
	// by the finalizer.
	require.True(t, kerrors.IsNotFound(r.client.Get(t.Context(),
		client.ObjectKeyFromObject(recording), &profilerecordingapi.ProfileRecording{})))
}

func TestBlockedRequeueDelay(t *testing.T) {
	t.Parallel()

	deletedAt := func(ago time.Duration) *profilerecordingapi.ProfileRecording {
		recording := testMergeRecording(
			profilerecordingapi.ProfileRecordingKindSeccompProfile,
			true,
		)
		recording.DeletionTimestamp = &metav1.Time{Time: time.Now().Add(-ago)}

		return recording
	}

	require.Equal(t, blockedRequeueMinDelay, blockedRequeueDelay(deletedAt(time.Second)))
	require.InDelta(
		t,
		time.Minute,
		blockedRequeueDelay(deletedAt(time.Minute)),
		float64(time.Second),
	)
	require.Equal(t, blockedRequeueMaxDelay, blockedRequeueDelay(deletedAt(time.Hour)))
}

func TestRecordingsBlockedBy(t *testing.T) {
	t.Parallel()

	deleted := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	live := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, false)
	live.Namespace = "other-ns"

	r := newMergeReconciler(t, deleted, live)

	require.Equal(t,
		[]reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(deleted)}},
		r.recordingsBlockedBy(t.Context(), partialSeccomp(testRecording+"-nginx", "nginx")))
	require.Empty(t, r.recordingsBlockedBy(t.Context(), partialSeccomp("unrelated-nginx", "nginx")))
}

// The owner check also has to hold when the profile appears between merging
// the existing profile and writing the result.
func TestCreateUpdateProfileRefusesForeignProfile(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)

	foreign := partialSeccomp(testRecording+"-nginx", "nginx", "exec")
	foreign.Labels = nil

	r := newMergeReconciler(t, recording, foreign)

	merged, err := newMergeableProfile(partialSeccomp("partial-a", "nginx", "read"))
	require.NoError(t, err)

	_, err = createUpdateProfile(
		t.Context(), r.client, recording, testRecording+"-nginx", merged,
		profilerecordingapi.ProfileRecordingKindSeccompProfile, nil, nil,
	)
	require.ErrorIs(t, err, util.ErrProfileOwnedByOtherRecording)
	require.ElementsMatch(t, []string{"exec"}, mergedSyscalls(t, r, "nginx"))
}

// An unknown kind has to be reported rather than silently doing nothing, while
// the partial profiles of the supported kinds still get merged.
func TestMergeProfilesUnknownKind(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording("NotAKind", true)
	r := newMergeReconciler(t, recording, partialSeccomp("partial-a", "nginx", "read"))

	requireMerged(t, r, recording)
	require.ElementsMatch(t, []string{"read"}, mergedSyscalls(t, r, "nginx"))

	recorder, ok := r.record.(*events.FakeRecorder)
	require.True(t, ok)
	require.Contains(t, <-recorder.Events, reasonCannotMergeKind)
}

// The kind of a recording can change while partial profiles of the former
// kind exist. They have to be merged into a profile of their kind, and the
// recording has to be released afterwards instead of being held forever.
func TestMergeProfilesAfterKindChange(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindAppArmorProfile, true)
	r := newMergeReconciler(t, recording,
		partialSeccomp("partial-a", "nginx", "read"),
		partialSeccomp("partial-b", "nginx", "write"),
	)

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: testRecording, Namespace: testNamespace},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"read", "write"}, mergedSyscalls(t, r, "nginx"))

	for _, name := range []string{"partial-a", "partial-b"} {
		require.True(t, kerrors.IsNotFound(r.client.Get(t.Context(),
			client.ObjectKey{Name: name}, &seccompprofile.SeccompProfile{})))
	}

	// Without its finalizer, the deleted recording is gone.
	require.True(t, kerrors.IsNotFound(r.client.Get(t.Context(),
		client.ObjectKeyFromObject(recording), &profilerecordingapi.ProfileRecording{})))
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

		requireMerged(t, r, recording)

		list := &apparmorprofileapi.AppArmorProfileList{}
		require.NoError(t, r.client.List(t.Context(), list))
		require.Empty(t, list.Items)
	})

	t.Run("selinux with no partial profiles", func(t *testing.T) {
		t.Parallel()

		recording := testMergeRecording(
			profilerecordingapi.ProfileRecordingKindSelinuxProfile, true)
		r := newMergeReconciler(t, recording)

		requireMerged(t, r, recording)
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

// A conflict while releasing the recording is retried against the API server:
// the cache may keep returning the version which lost the conflict.
func TestReleaseRecordingRetriesAgainstAPIReader(t *testing.T) {
	t.Parallel()

	base := fake.NewClientBuilder().
		WithScheme(mergerTestScheme(t)).
		WithObjects(testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, false)).
		Build()

	key := types.NamespacedName{Name: testRecording, Namespace: testNamespace}
	stale := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, base.Get(t.Context(), key, stale))

	// Another writer adds a finalizer in front of the one of the recording
	// after the cache saw it, which moves it.
	current := stale.DeepCopy()
	current.Labels = map[string]string{"other": "writer"}
	current.Finalizers = append([]string{"example.com/other"}, current.Finalizers...)
	require.NoError(t, base.Update(t.Context(), current))

	// Like the API server, reject a JSON patch which does not apply as
	// invalid.
	server := interceptor.NewClient(base, interceptor.Funcs{
		Patch: func(
			ctx context.Context, cl client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			var statusErr *kerrors.StatusError

			err := cl.Patch(ctx, obj, patch, opts...)
			if err != nil && !errors.As(err, &statusErr) {
				return kerrors.NewGenericServerResponse(
					http.StatusUnprocessableEntity,
					"PATCH",
					schema.GroupResource{},
					"",
					err.Error(),
					0,
					false,
				)
			}

			return err
		},
	})

	staleCache := interceptor.NewClient(server, interceptor.Funcs{
		Get: func(
			_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object,
			_ ...client.GetOption,
		) error {
			rec, ok := obj.(*profilerecordingapi.ProfileRecording)
			require.True(t, ok)
			stale.DeepCopyInto(rec)

			return nil
		},
	})

	r := &PolicyMergeReconciler{
		client: staleCache,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(20),
	}

	// Every retry against the cache reads the stale version again.
	err := r.releaseRecording(t.Context(), stale.DeepCopy())
	require.True(t, kerrors.IsConflict(err), err)

	r.reader = base
	require.NoError(t, r.releaseRecording(t.Context(), stale.DeepCopy()))

	released := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, base.Get(t.Context(), key, released))
	require.Equal(t, []string{"example.com/other"}, released.Finalizers)
	require.Equal(t, "writer", released.Labels["other"])
}

// Changes of another writer which leave the finalizer in place do not fail the
// release, even if the cache does not show them yet: the patch only touches
// the finalizer.
func TestReleaseRecordingWithOutdatedCache(t *testing.T) {
	t.Parallel()

	base := fake.NewClientBuilder().
		WithScheme(mergerTestScheme(t)).
		WithObjects(testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, false)).
		Build()

	key := types.NamespacedName{Name: testRecording, Namespace: testNamespace}
	stale := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, base.Get(t.Context(), key, stale))

	current := stale.DeepCopy()
	current.Labels = map[string]string{"other": "writer"}
	current.Finalizers = append(current.Finalizers, "example.com/other")
	require.NoError(t, base.Update(t.Context(), current))

	staleCache := interceptor.NewClient(base, interceptor.Funcs{
		Get: func(
			_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object,
			_ ...client.GetOption,
		) error {
			rec, ok := obj.(*profilerecordingapi.ProfileRecording)
			require.True(t, ok)
			stale.DeepCopyInto(rec)

			return nil
		},
	})

	r := &PolicyMergeReconciler{
		client: staleCache,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(20),
	}

	require.NoError(t, r.releaseRecording(t.Context(), stale.DeepCopy()))

	released := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, base.Get(t.Context(), key, released))
	require.Equal(t, []string{"example.com/other"}, released.Finalizers)
	require.Equal(t, "writer", released.Labels["other"])
}

// The cache may still show the partial profiles which the merge just deleted,
// so the release lists them from the API server. Otherwise the recording would
// keep its finalizer without anything reconciling it again.
func TestReleaseRecordingListsPartialProfilesFromAPIReader(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	scheme := mergerTestScheme(t)

	staleCache := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(recording.DeepCopy(), partialSeccomp("partial-a", "nginx", "read")).
		Build()
	apiServer := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(recording.DeepCopy()).
		Build()

	r := &PolicyMergeReconciler{
		client: staleCache,
		log:    logr.Discard(),
		record: events.NewFakeRecorder(20),
	}

	// The partial profile in the cache keeps the recording.
	require.NoError(t, r.releaseRecording(t.Context(), recording.DeepCopy()))
	require.NoError(t, staleCache.Get(t.Context(), client.ObjectKeyFromObject(recording),
		&profilerecordingapi.ProfileRecording{}))

	// The API server knows that it is gone.
	r.reader = apiServer
	require.NoError(t, r.releaseRecording(t.Context(), recording.DeepCopy()))
	require.True(t, kerrors.IsNotFound(staleCache.Get(t.Context(),
		client.ObjectKeyFromObject(recording), &profilerecordingapi.ProfileRecording{})))
}
