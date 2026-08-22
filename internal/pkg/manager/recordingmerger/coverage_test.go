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

package recordingmerger

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// seccompPartial builds a mergeable seccomp partial profile from a set of rules,
// where each rule is a (action, names) pair.
func seccompPartial(name string, rules ...seccompprofile.Syscall) mergeableProfile {
	return &mergeableSeccompProfile{
		SeccompProfile: seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: seccompprofile.SeccompProfileSpec{
				DefaultAction: seccompprofile.ActErrno,
				Syscalls:      rules,
			},
		},
	}
}

func allow(names ...string) seccompprofile.Syscall {
	return seccompprofile.Syscall{Action: seccompprofile.ActAllow, Names: names}
}

// parseCoverage unmarshals the annotation value into the coverage struct.
func parseCoverage(t *testing.T, value string) syscallCoverage {
	t.Helper()

	var cov syscallCoverage
	require.NoError(t, json.Unmarshal([]byte(value), &cov))

	return cov
}

func TestSeccompCoverageAnnotation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		partials     []mergeableProfile
		expectEmpty  bool
		expectTotal  int
		expectCounts map[string]int
	}{
		{
			name: "heterogeneous",
			partials: []mergeableProfile{
				seccompPartial("a", allow("read", "write", "openat")),
				seccompPartial("b", allow("read", "write", "socket")),
				seccompPartial("c", allow("read", "write")),
			},
			expectTotal:  3,
			expectCounts: map[string]int{"read": 3, "write": 3, "openat": 1, "socket": 1},
		},
		{
			// All counts equal the total; no values are suppressed.
			name: "homogeneous",
			partials: []mergeableProfile{
				seccompPartial("a", allow("read", "write")),
				seccompPartial("b", allow("read", "write")),
				seccompPartial("c", allow("read", "write")),
			},
			expectTotal:  3,
			expectCounts: map[string]int{"read": 3, "write": 3},
		},
		{
			// A single partial still produces coverage with total=1.
			name: "single partial",
			partials: []mergeableProfile{
				seccompPartial("a", allow("read", "write")),
			},
			expectTotal:  1,
			expectCounts: map[string]int{"read": 1, "write": 1},
		},
		{
			// Duplicate names within one rule count once for that partial.
			name: "duplicate names in one rule",
			partials: []mergeableProfile{
				seccompPartial("a", allow("read", "read", "write")),
				seccompPartial("b", allow("read")),
			},
			expectTotal:  2,
			expectCounts: map[string]int{"read": 2, "write": 1},
		},
		{
			// The same syscall across multiple rules in one partial counts once.
			name: "same syscall across multiple rules",
			partials: []mergeableProfile{
				seccompPartial("a", allow("read"), allow("read")),
				seccompPartial("b", allow("write")),
			},
			expectTotal:  2,
			expectCounts: map[string]int{"read": 1, "write": 1},
		},
		{
			// Counting is by syscall name across rules, regardless of action.
			name: "different actions",
			partials: []mergeableProfile{
				seccompPartial("a",
					allow("read"),
					seccompprofile.Syscall{Action: seccompprofile.ActLog, Names: []string{"write"}},
				),
				seccompPartial("b", allow("read")),
			},
			expectTotal:  2,
			expectCounts: map[string]int{"read": 2, "write": 1},
		},
		{
			// A partial with no syscall rules still contributes to the total.
			name: "empty rules",
			partials: []mergeableProfile{
				seccompPartial("a", allow("read")),
				seccompPartial("b"),
			},
			expectTotal:  2,
			expectCounts: map[string]int{"read": 1},
		},
		{
			name: "empty names list",
			partials: []mergeableProfile{
				seccompPartial("a", allow()),
				seccompPartial("b", allow("read")),
			},
			expectTotal:  2,
			expectCounts: map[string]int{"read": 1},
		},
		{
			// No included partial profiles produce no annotation.
			name:        "no partials",
			partials:    []mergeableProfile{},
			expectEmpty: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			value, err := seccompCoverageAnnotation(tc.partials)
			require.NoError(t, err)

			if tc.expectEmpty {
				require.Empty(t, value)

				return
			}

			require.NotEmpty(t, value)

			cov := parseCoverage(t, value)
			require.Equal(t, syscallCoverageSchemaVersion, cov.Version)
			require.Equal(t, tc.expectTotal, cov.Total)
			require.Equal(t, tc.expectCounts, cov.Syscalls)
		})
	}
}

// SELinux and AppArmor profiles are excluded.
func TestSeccompCoverageAnnotation_NonSeccompExcluded(t *testing.T) {
	t.Parallel()

	selinuxPartials := []mergeableProfile{
		&MergeableSelinuxProfile{
			SelinuxProfile: selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "sel"},
			},
		},
	}
	value, err := seccompCoverageAnnotation(selinuxPartials)
	require.NoError(t, err)
	require.Empty(t, value)

	apparmorPartials := []mergeableProfile{
		&mergeableAppArmorProfile{
			AppArmorProfile: apparmorprofileapi.AppArmorProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "aa"},
			},
		},
	}
	value, err = seccompCoverageAnnotation(apparmorPartials)
	require.NoError(t, err)
	require.Empty(t, value)
}

func TestSeccompCoverageAnnotation_DeterministicAndOrderIndependent(t *testing.T) {
	t.Parallel()

	base := []mergeableProfile{
		seccompPartial("a", allow("read", "write", "openat")),
		seccompPartial("b", allow("read", "write", "socket")),
		seccompPartial("c", allow("read", "write", "mmap")),
	}

	// Repeated calls on the same input are byte-identical.
	first, err := seccompCoverageAnnotation(base)
	require.NoError(t, err)

	for range 20 {
		again, aerr := seccompCoverageAnnotation(base)
		require.NoError(t, aerr)
		require.Equal(t, first, again)
	}

	// Shuffled input order yields an identical serialized value.
	shuffles := [][]mergeableProfile{
		{base[2], base[0], base[1]},
		{base[1], base[2], base[0]},
		{base[2], base[1], base[0]},
	}
	for _, shuffled := range shuffles {
		value, verr := seccompCoverageAnnotation(shuffled)
		require.NoError(t, verr)
		require.Equal(t, first, value)
	}
}

func TestSeccompCoverageAnnotation_DoesNotMutateSources(t *testing.T) {
	t.Parallel()

	original := seccompprofile.SeccompProfileSpec{
		DefaultAction: seccompprofile.ActErrno,
		Syscalls: []seccompprofile.Syscall{
			{Action: seccompprofile.ActAllow, Names: []string{"read", "read", "write"}},
			{Action: seccompprofile.ActLog, Names: []string{"read"}},
		},
	}

	partial := &mergeableSeccompProfile{
		SeccompProfile: seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "a"},
			Spec:       *original.DeepCopy(),
		},
	}

	_, err := seccompCoverageAnnotation([]mergeableProfile{partial})
	require.NoError(t, err)

	// Spec (including exact rule and name ordering) is untouched.
	require.Equal(t, original, partial.Spec)
}

// The merge path computes coverage from each group's own partials independently,
// so two independent calls produce independent, non-interfering results.
func TestSeccompCoverageAnnotation_NoCrossGroupLeak(t *testing.T) {
	t.Parallel()

	groupA := []mergeableProfile{
		seccompPartial("a1", allow("read", "openat")),
		seccompPartial("a2", allow("read")),
	}
	groupB := []mergeableProfile{
		seccompPartial("b1", allow("write", "socket")),
	}

	valueA, err := seccompCoverageAnnotation(groupA)
	require.NoError(t, err)
	valueB, err := seccompCoverageAnnotation(groupB)
	require.NoError(t, err)

	covA := parseCoverage(t, valueA)
	covB := parseCoverage(t, valueB)

	require.Equal(t, 2, covA.Total)
	require.Equal(t, map[string]int{"read": 2, "openat": 1}, covA.Syscalls)

	require.Equal(t, 1, covB.Total)
	require.Equal(t, map[string]int{"write": 1, "socket": 1}, covB.Syscalls)

	// No group-A syscalls appear in group B and vice versa.
	require.NotContains(t, covB.Syscalls, "read")
	require.NotContains(t, covB.Syscalls, "openat")
	require.NotContains(t, covA.Syscalls, "write")
	require.NotContains(t, covA.Syscalls, "socket")
}

func TestSetSyscallCoverageAnnotation(t *testing.T) {
	t.Parallel()

	t.Run("nil annotations map is initialized safely", func(t *testing.T) {
		t.Parallel()

		obj := &seccompprofile.SeccompProfile{}

		require.NotPanics(t, func() {
			setSyscallCoverageAnnotation(obj, `{"version":"v1","total":1,"syscalls":{"read":1}}`)
		})
		require.JSONEq(t,
			`{"version":"v1","total":1,"syscalls":{"read":1}}`,
			obj.GetAnnotations()[syscallCoverageAnnotation])
	})

	t.Run("preserves existing unrelated annotations", func(t *testing.T) {
		t.Parallel()

		obj := &seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{"user.example.com/keep": "yes"},
			},
		}
		setSyscallCoverageAnnotation(obj, "cov-value")

		require.Equal(t, "yes", obj.GetAnnotations()["user.example.com/keep"])
		require.Equal(t, "cov-value", obj.GetAnnotations()[syscallCoverageAnnotation])
	})

	t.Run("refreshes stale coverage value", func(t *testing.T) {
		t.Parallel()

		obj := &seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					syscallCoverageAnnotation: "stale",
					"user.example.com/keep":   "yes",
				},
			},
		}
		setSyscallCoverageAnnotation(obj, "fresh")

		require.Equal(t, "fresh", obj.GetAnnotations()[syscallCoverageAnnotation])
		require.Equal(t, "yes", obj.GetAnnotations()["user.example.com/keep"])
	})

	t.Run("empty value is a no-op", func(t *testing.T) {
		t.Parallel()

		obj := &seccompprofile.SeccompProfile{}
		setSyscallCoverageAnnotation(obj, "")
		require.Nil(t, obj.GetAnnotations())
	})
}

// This guards against the coverage work accidentally altering merged spec output.
func TestMergeProfiles_SeccompUnionUnchanged(t *testing.T) {
	t.Parallel()

	partials := []client.Object{
		&seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "a"},
			Spec: seccompprofile.SeccompProfileSpec{
				DefaultAction: seccompprofile.ActErrno,
				Syscalls: []seccompprofile.Syscall{
					{Action: seccompprofile.ActAllow, Names: []string{"read", "write", "openat"}},
				},
			},
		},
		&seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "b"},
			Spec: seccompprofile.SeccompProfileSpec{
				DefaultAction: seccompprofile.ActErrno,
				Syscalls: []seccompprofile.Syscall{
					{Action: seccompprofile.ActAllow, Names: []string{"read", "write", "socket"}},
				},
			},
		},
	}

	merged, err := MergeProfiles(partials)
	require.NoError(t, err)

	// Verify that the merged profile still contains the same syscall union,
	// regardless of how the merger groups syscall names into rules.
	sorted := ifaceAsSortedSeccompProfile(merged)
	require.NotNil(t, sorted)

	names := make([]string, 0, len(sorted.Spec.Syscalls))

	for _, rule := range sorted.Spec.Syscalls {
		require.Equal(t, seccompprofile.ActAllow, rule.Action)
		names = append(names, rule.Names...)
	}

	sort.Strings(names)

	require.Equal(
		t,
		[]string{"openat", "read", "socket", "write"},
		names,
	)

	// The merge itself never sets the coverage annotation; that is done in the
	// controller path (createUpdateProfile), not in MergeProfiles.
	require.NotContains(t, merged.GetAnnotations(), syscallCoverageAnnotation)
}

func TestSeccompCoverageAnnotation_MustRunBeforeMerge(t *testing.T) {
	t.Parallel()

	partials := []mergeableProfile{
		seccompPartial("a", allow("read", "write")),
		seccompPartial("b", allow("read", "socket")),
	}

	merged, err := mergeMergeableProfiles(partials)
	require.NoError(t, err)
	require.Same(t, partials[0], merged)

	// This intentionally demonstrates the invalid ordering: merging mutates the
	// first partial, so computing coverage afterward inflates socket's count.
	coverageAnnotation, err := seccompCoverageAnnotation(partials)
	require.NoError(t, err)

	coverage := parseCoverage(t, coverageAnnotation)
	require.Equal(t, 2, coverage.Syscalls["socket"])
}

func TestMergeTypedProfiles_ComputesCoverageBeforeMerge(t *testing.T) {
	t.Parallel()

	const (
		recordingName = "rec"
		namespace     = "ns"
		containerName = "ctr"
	)

	partialLabels := map[string]string{
		profilerecordingapi.ProfileToRecordingLabel:          recordingName,
		profilerecordingapi.ProfileToRecordingNamespaceLabel: namespace,
		profilerecordingapi.ProfileToContainerLabel:          containerName,
		profilebase.ProfilePartialLabel:                      "true",
	}
	partialA := &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: namespace, Labels: partialLabels},
		Spec: seccompprofile.SeccompProfileSpec{
			DefaultAction: seccompprofile.ActErrno,
			Syscalls:      []seccompprofile.Syscall{allow("read", "write")},
		},
	}
	partialB := &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: namespace, Labels: partialLabels},
		Spec: seccompprofile.SeccompProfileSpec{
			DefaultAction: seccompprofile.ActErrno,
			Syscalls:      []seccompprofile.Syscall{allow("read", "socket")},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(coverageTestScheme(t)).
		WithObjects(partialA, partialB).
		Build()
	reconciler := &PolicyMergeReconciler{client: cl, log: logr.Discard()}
	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: recordingName, Namespace: namespace},
	}

	createCalled := false
	err := reconciler.mergeTypedProfiles(
		context.Background(), recording,
		func(
			_ context.Context,
			_ client.Client,
			_ *profilerecordingapi.ProfileRecording,
			_ string,
			merged mergeableProfile,
			coverageAnnotation string,
		) (controllerutil.OperationResult, error) {
			createCalled = true

			coverage := parseCoverage(t, coverageAnnotation)
			require.Equal(t, 2, coverage.Total)
			require.Equal(t, map[string]int{"read": 2, "socket": 1, "write": 1}, coverage.Syscalls)

			mergedProfile := ifaceAsSortedSeccompProfile(merged.getProfile())
			require.NotNil(t, mergedProfile)

			names := make([]string, 0, len(mergedProfile.Spec.Syscalls))
			for _, syscall := range mergedProfile.Spec.Syscalls {
				names = append(names, syscall.Names...)
			}

			sort.Strings(names)
			require.Equal(t, []string{"read", "socket", "write"}, names)

			return controllerutil.OperationResultNone, nil
		},
		&seccompprofile.SeccompProfile{},
		&seccompprofile.SeccompProfileList{},
	)
	require.NoError(t, err)
	require.True(t, createCalled)
}

func coverageTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, seccompprofile.AddToScheme(scheme))
	require.NoError(t, selinuxprofileapi.AddToScheme(scheme))
	require.NoError(t, apparmorprofileapi.AddToScheme(scheme))

	return scheme
}

// Integration test around the actual controller wiring: createUpdateProfile must
// set the coverage annotation only on merged SeccompProfiles, never on SELinux or
// AppArmor, and must preserve pre-existing annotations on update.
func TestCreateUpdateProfile_CoverageAnnotation(t *testing.T) {
	t.Parallel()

	const (
		recordingName = "rec"
		namespace     = "ns"
		mergedName    = "rec-ctr"
		coverage      = `{"version":"v1","total":2,"syscalls":{"read":2}}`
	)

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: recordingName, Namespace: namespace},
	}

	t.Run("seccomp merged profile receives the annotation", func(t *testing.T) {
		t.Parallel()

		cl := fake.NewClientBuilder().WithScheme(coverageTestScheme(t)).Build()

		_, err := createUpdateProfile(
			context.Background(), cl, recording, mergedName,
			&mergeableSeccompProfile{}, profilerecordingapi.ProfileRecordingKindSeccompProfile, coverage)
		require.NoError(t, err)

		got := &seccompprofile.SeccompProfile{}
		require.NoError(t, cl.Get(context.Background(),
			client.ObjectKey{Name: mergedName}, got))
		require.JSONEq(t, coverage, got.GetAnnotations()[syscallCoverageAnnotation])
	})

	t.Run("selinux merged profile never receives the annotation", func(t *testing.T) {
		t.Parallel()

		cl := fake.NewClientBuilder().WithScheme(coverageTestScheme(t)).Build()

		_, err := createUpdateProfile(
			context.Background(), cl, recording, mergedName,
			&MergeableSelinuxProfile{}, profilerecordingapi.ProfileRecordingKindSelinuxProfile, coverage)
		require.NoError(t, err)

		got := &selinuxprofileapi.SelinuxProfile{}
		require.NoError(t, cl.Get(context.Background(),
			client.ObjectKey{Name: mergedName}, got))
		require.NotContains(t, got.GetAnnotations(), syscallCoverageAnnotation)
	})

	t.Run("apparmor merged profile never receives the annotation", func(t *testing.T) {
		t.Parallel()

		cl := fake.NewClientBuilder().WithScheme(coverageTestScheme(t)).Build()

		_, err := createUpdateProfile(
			context.Background(), cl, recording, mergedName,
			&mergeableAppArmorProfile{}, profilerecordingapi.ProfileRecordingKindAppArmorProfile, coverage)
		require.NoError(t, err)

		got := &apparmorprofileapi.AppArmorProfile{}
		require.NoError(t, cl.Get(context.Background(),
			client.ObjectKey{Name: mergedName}, got))
		require.NotContains(t, got.GetAnnotations(), syscallCoverageAnnotation)
	})

	t.Run("existing annotations are preserved on update", func(t *testing.T) {
		t.Parallel()

		existing := &seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:        mergedName,
				Annotations: map[string]string{"user.example.com/keep": "yes"},
			},
		}
		cl := fake.NewClientBuilder().
			WithScheme(coverageTestScheme(t)).WithObjects(existing).Build()

		_, err := createUpdateProfile(
			context.Background(), cl, recording, mergedName,
			&mergeableSeccompProfile{}, profilerecordingapi.ProfileRecordingKindSeccompProfile, coverage)
		require.NoError(t, err)

		got := &seccompprofile.SeccompProfile{}
		require.NoError(t, cl.Get(context.Background(),
			client.ObjectKey{Name: mergedName}, got))
		require.JSONEq(t, coverage, got.GetAnnotations()[syscallCoverageAnnotation])
		require.Equal(t, "yes", got.GetAnnotations()["user.example.com/keep"])
	})
}
