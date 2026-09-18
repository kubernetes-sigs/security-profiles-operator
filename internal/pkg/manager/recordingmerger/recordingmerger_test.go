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
	"k8s.io/client-go/tools/record"
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
		record: record.NewFakeRecorder(20),
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
