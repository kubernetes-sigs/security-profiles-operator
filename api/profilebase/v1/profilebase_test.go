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

package v1_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingv1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofilev1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func recordedProfile(name, recording, namespace string) *seccompprofilev1.SeccompProfile {
	return &seccompprofilev1.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				profilerecordingv1.ProfileToRecordingLabel:          recording,
				profilerecordingv1.ProfileToRecordingNamespaceLabel: namespace,
			},
		},
	}
}

func TestListProfilesByRecording(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, seccompprofilev1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		recordedProfile("a", "rec", "ns"),
		recordedProfile("b", "rec", "ns"),
		// The same recording name in another namespace is another recording.
		recordedProfile("c", "rec", "other"),
		recordedProfile("d", "other", "ns"),
		&seccompprofilev1.SeccompProfile{ObjectMeta: metav1.ObjectMeta{Name: "unlabeled"}},
	).Build()

	profiles, err := profilebasev1.ListProfilesByRecording(
		t.Context(), cli, "rec", "ns", &seccompprofilev1.SeccompProfileList{},
	)
	require.NoError(t, err)

	names := make([]string, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.GetName())
	}

	require.ElementsMatch(t, []string{"a", "b"}, names)

	// The method of the profile type uses the same lookup.
	profiles, err = (&seccompprofilev1.SeccompProfile{}).ListProfilesByRecording(
		t.Context(),
		cli,
		"rec",
		"other",
	)
	require.NoError(t, err)
	require.Len(t, profiles, 1)
	require.Equal(t, "c", profiles[0].GetName())

	profiles, err = profilebasev1.ListProfilesByRecording(
		t.Context(), cli, "missing", "ns", &seccompprofilev1.SeccompProfileList{},
	)
	require.NoError(t, err)
	require.Empty(t, profiles)
}

func TestListProfilesByRecordingError(t *testing.T) {
	t.Parallel()

	errList := errors.New("list failed")

	scheme := runtime.NewScheme()
	require.NoError(t, seccompprofilev1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
			return errList
		},
	}).Build()

	_, err := profilebasev1.ListProfilesByRecording(
		t.Context(), cli, "rec", "ns", &seccompprofilev1.SeccompProfileList{},
	)
	require.ErrorIs(t, err, errList)
}

func TestIsPartialDisabledReconcilable(t *testing.T) {
	t.Parallel()

	profile := &seccompprofilev1.SeccompProfile{}
	require.False(t, profilebasev1.IsPartial(profile))
	require.False(t, profilebasev1.IsDisabled(&profile.Spec.SpecBase))
	require.True(t, profilebasev1.IsReconcilable(profile))

	profile.Labels = map[string]string{profilebasev1.ProfilePartialLabel: "true"}
	require.True(t, profilebasev1.IsPartial(profile))
	require.False(t, profilebasev1.IsReconcilable(profile))

	profile.Labels = nil
	profile.Spec.State = profilebasev1.SpecStateDisabled
	require.True(t, profilebasev1.IsDisabled(&profile.Spec.SpecBase))
	require.False(t, profilebasev1.IsReconcilable(profile))
}
