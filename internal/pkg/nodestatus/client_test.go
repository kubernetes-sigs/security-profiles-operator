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

package nodestatus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const testNode = "worker-1"

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, seccompprofile.AddToScheme(s))
	require.NoError(t, secprofnodestatusapi.AddToScheme(s))
	require.NoError(t, profilerecordingapi.AddToScheme(s))

	return s
}

// newFakeClient returns a fake client that, like the cache backed client of
// the manager, returns objects with their type meta set. The status client
// derives the status names from the kind of the profile.
func newFakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()

	scheme := testScheme(t)

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context,
				c client.WithWatch,
				key client.ObjectKey,
				obj client.Object,
				opts ...client.GetOption,
			) error {
				if err := c.Get(ctx, key, obj, opts...); err != nil {
					return err
				}

				gvk, err := apiutil.GVKForObject(obj, scheme)
				if err != nil {
					return err
				}

				obj.GetObjectKind().SetGroupVersionKind(gvk)

				return nil
			},
		}).
		Build()
}

// newStatusClient builds a StatusClient without reading the node name from
// the environment, so that tests can run in parallel. The kind is resolved
// like NewForProfile does, with the scheme of the tests.
func newStatusClient(
	t *testing.T, pol profilebase.SecurityProfileBase, c client.Client,
) *StatusClient {
	t.Helper()

	kind, err := profileKind(pol, newFakeClient(t))
	require.NoError(t, err)

	return &StatusClient{
		pol:             pol,
		kind:            kind,
		nodeName:        testNode,
		finalizerString: getFinalizerString(pol, testNode),
		client:          c,
	}
}

// storedProfile returns the profile as it is stored by the client.
func storedProfile(t *testing.T, c client.Client, name string) *seccompprofile.SeccompProfile {
	t.Helper()

	sp := &seccompprofile.SeccompProfile{}
	require.NoError(t, c.Get(context.Background(), util.NamespacedName(name, "test-namespace"), sp))

	return sp
}

func nodeStatus(
	t *testing.T, c client.Client, name string,
) (*secprofnodestatusapi.SecurityProfileNodeStatus, error) {
	t.Helper()

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	err := c.Get(context.Background(), util.NamespacedName(name, "test-namespace"), status)

	return status, err
}

// preparedProfile returns a profile that already carries the node finalizer
// and the status label, as it looks after the first reconcile.
func preparedProfile() *seccompprofile.SeccompProfile {
	sp := regularSeccompProfile()
	sp.Finalizers = []string{util.GetFinalizerNodeString(testNode)}
	sp.Labels = map[string]string{
		secprofnodestatusapi.StatusToProfLabel: util.KindBasedDNSLengthName(sp),
	}

	return sp
}

const wantStatusName = "seccompprofile-test-profile-" + testNode

func TestCreateInitialStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*seccompprofile.SeccompProfile)
		want   secprofnodestatusapi.ProfileState
	}{
		{
			name: "Pending",
			want: secprofnodestatusapi.ProfileStatePending,
		},
		{
			name: "Disabled",
			mutate: func(sp *seccompprofile.SeccompProfile) {
				sp.Spec.State = profilebase.SpecStateDisabled
			},
			want: secprofnodestatusapi.ProfileStateDisabled,
		},
		{
			name: "Partial",
			mutate: func(sp *seccompprofile.SeccompProfile) {
				sp.Finalizers = []string{partialProfileFinalizer}
				sp.Labels[profilebase.ProfilePartialLabel] = "true"
			},
			want: secprofnodestatusapi.ProfileStatePartial,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sp := preparedProfile()
			if tc.mutate != nil {
				tc.mutate(sp)
			}

			c := newFakeClient(t, sp.DeepCopy())
			sc := newStatusClient(t, sp, c)

			migrated, err := sc.Create(context.Background())
			require.NoError(t, err)
			require.False(t, migrated)

			status, err := nodeStatus(t, c, wantStatusName)
			require.NoError(t, err)
			require.Equal(t, tc.want, status.Status.Status)
			require.Equal(t, testNode, status.Spec.NodeName)
			require.Equal(t, string(tc.want), status.Labels[secprofnodestatusapi.StatusStateLabel])
			require.Equal(t, testNode, status.Labels[secprofnodestatusapi.StatusToNodeLabel])
			require.Equal(t, "SeccompProfile", status.Labels[secprofnodestatusapi.StatusKindLabel])
			require.Equal(t,
				"SeccompProfile-test-profile",
				status.Labels[secprofnodestatusapi.StatusToProfLabel],
			)

			owner := metav1.GetControllerOf(status)
			require.NotNil(t, owner)
			require.Equal(t, "test-profile", owner.Name)
			require.Equal(t, "SeccompProfile", owner.Kind)

			exists, err := sc.Exists(context.Background())
			require.NoError(t, err)
			require.True(t, exists)
		})
	}
}

func TestCreateResetsExistingStatus(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	existing := newStatusClient(t, sp, nil).statusObj(secprofnodestatusapi.ProfileStateInstalled)

	c := newFakeClient(t, sp.DeepCopy(), existing)
	sc := newStatusClient(t, sp, c)

	_, err := sc.Create(context.Background())
	require.NoError(t, err)

	status, err := nodeStatus(t, c, wantStatusName)
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, status.Status.Status)
}

func TestCreateMigratesLegacyStatus(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	legacy := &secprofnodestatusapi.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile-" + testNode,
			Namespace: "test-namespace",
			Labels: map[string]string{
				secprofnodestatusapi.StatusToProfLabel: util.KindBasedDNSLengthName(sp),
			},
		},
	}

	c := newFakeClient(t, sp.DeepCopy(), legacy)
	sc := newStatusClient(t, sp, c)

	migrated, err := sc.Create(context.Background())
	require.NoError(t, err)
	require.True(t, migrated)

	_, err = nodeStatus(t, c, legacy.Name)
	require.True(t, kerrors.IsNotFound(err))

	_, err = nodeStatus(t, c, wantStatusName)
	require.NoError(t, err)
}

func TestExists(t *testing.T) {
	t.Parallel()

	withoutFinalizer := preparedProfile()
	withoutFinalizer.Finalizers = nil

	cases := []struct {
		name       string
		profile    *seccompprofile.SeccompProfile
		withStatus bool
		want       bool
	}{
		{name: "FinalizerAndStatus", profile: preparedProfile(), withStatus: true, want: true},
		{name: "FinalizerOnly", profile: preparedProfile(), want: false},
		{name: "StatusOnly", profile: withoutFinalizer, withStatus: true, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			objs := []client.Object{tc.profile.DeepCopy()}
			if tc.withStatus {
				objs = append(
					objs,
					newStatusClient(
						t,
						tc.profile,
						nil,
					).statusObj(secprofnodestatusapi.ProfileStatePending),
				)
			}

			sc := newStatusClient(t, tc.profile, newFakeClient(t, objs...))

			got, err := sc.Exists(context.Background())
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSetNodeStatusAndMatches(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	existing := newStatusClient(t, sp, nil).statusObj(secprofnodestatusapi.ProfileStatePending)
	c := newFakeClient(t, sp.DeepCopy(), existing)
	sc := newStatusClient(t, sp, c)
	ctx := context.Background()

	matches, err := sc.Matches(ctx, secprofnodestatusapi.ProfileStateInstalled)
	require.NoError(t, err)
	require.False(t, matches)

	require.NoError(t, sc.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateInstalled))

	status, err := nodeStatus(t, c, wantStatusName)
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, status.Status.Status)
	require.Equal(t,
		string(secprofnodestatusapi.ProfileStateInstalled),
		status.Labels[secprofnodestatusapi.StatusStateLabel],
	)

	matches, err = sc.Matches(ctx, secprofnodestatusapi.ProfileStateInstalled)
	require.NoError(t, err)
	require.True(t, matches)
}

func TestSetNodeStatusWithoutStatusObject(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	sc := newStatusClient(t, sp, newFakeClient(t, sp.DeepCopy()))
	ctx := context.Background()

	// Terminating a profile whose status is already gone is fine.
	require.NoError(t, sc.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateTerminating))

	matches, err := sc.Matches(ctx, secprofnodestatusapi.ProfileStateTerminating)
	require.NoError(t, err)
	require.True(t, matches)

	// Any other state needs the status object.
	require.Error(t, sc.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateInstalled))

	_, err = sc.Matches(ctx, secprofnodestatusapi.ProfileStateInstalled)
	require.Error(t, err)
}

func TestAnnotations(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	existing := newStatusClient(t, sp, nil).statusObj(secprofnodestatusapi.ProfileStatePending)
	c := newFakeClient(t, sp.DeepCopy(), existing)
	sc := newStatusClient(t, sp, c)
	ctx := context.Background()

	value, err := sc.GetAnnotation(ctx, "key")
	require.NoError(t, err)
	require.Empty(t, value)

	require.NoError(t, sc.SetAnnotation(ctx, "key", "value"))

	status, err := nodeStatus(t, c, wantStatusName)
	require.NoError(t, err)

	version := status.ResourceVersion

	value, err = sc.GetAnnotation(ctx, "key")
	require.NoError(t, err)
	require.Equal(t, "value", value)

	// Setting the same value again does not write the object.
	require.NoError(t, sc.SetAnnotation(ctx, "key", "value"))

	status, err = nodeStatus(t, c, wantStatusName)
	require.NoError(t, err)
	require.Equal(t, version, status.ResourceVersion)
}

func TestAnnotationsWithoutStatusObject(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	sc := newStatusClient(t, sp, newFakeClient(t, sp.DeepCopy()))

	_, err := sc.GetAnnotation(context.Background(), "key")
	require.Error(t, err)
	require.Error(t, sc.SetAnnotation(context.Background(), "key", "value"))
}

func TestRemove(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	c := newFakeClient(t, sp.DeepCopy())
	sc := newStatusClient(t, sp, c)

	require.NoError(t, sc.Remove(context.Background(), c))
	require.NotContains(t, storedProfile(t, c, sp.Name).Finalizers, sc.finalizerString)

	// Removing again finds neither finalizer nor status and succeeds.
	require.NoError(t, sc.Remove(context.Background(), c))
}

func TestRemoveNodeStatus(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	existing := newStatusClient(t, sp, nil).statusObj(secprofnodestatusapi.ProfileStatePending)
	c := newFakeClient(t, sp.DeepCopy(), existing)
	sc := newStatusClient(t, sp, c)

	require.NoError(t, sc.removeNodeStatus(context.Background(), c))

	_, err := nodeStatus(t, c, wantStatusName)
	require.True(t, kerrors.IsNotFound(err))

	// A status that is already gone is not an error.
	require.NoError(t, sc.removeNodeStatus(context.Background(), c))
}

func recordedPartialProfile(name string) *seccompprofile.SeccompProfile {
	sp := preparedProfile()
	sp.Name = name
	sp.Finalizers = []string{partialProfileFinalizer}
	sp.Labels = map[string]string{
		profilebase.ProfilePartialLabel:                      "true",
		profilerecordingapi.ProfileToRecordingLabel:          "recording",
		profilerecordingapi.ProfileToRecordingNamespaceLabel: "test-namespace",
	}

	return sp
}

func testRecording() *profilerecordingapi.ProfileRecording {
	return &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "recording",
			Namespace:  "test-namespace",
			Finalizers: []string{profilerecordingapi.RecordingHasUnmergedProfiles},
		},
	}
}

func recordingHasFinalizer(t *testing.T, c client.Client) bool {
	t.Helper()

	pr := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(
		context.Background(), util.NamespacedName("recording", "test-namespace"), pr,
	))

	return controllerutil.ContainsFinalizer(pr, profilerecordingapi.RecordingHasUnmergedProfiles)
}

func TestRemovePartialProfileReleasesRecording(t *testing.T) {
	t.Parallel()

	sp := recordedPartialProfile("test-profile")
	c := newFakeClient(t, sp.DeepCopy(), testRecording())
	sc := newStatusClient(t, sp, c)

	require.NoError(t, sc.Remove(context.Background(), c))

	// The last partial profile of a recording lets the recording go.
	require.False(t, recordingHasFinalizer(t, c))
	require.NotContains(t, storedProfile(t, c, sp.Name).Finalizers, partialProfileFinalizer)
}

func TestRemovePartialProfileKeepsRecordingWithOtherPartials(t *testing.T) {
	t.Parallel()

	sp := recordedPartialProfile("test-profile")
	other := recordedPartialProfile("other-profile")
	c := newFakeClient(t, sp.DeepCopy(), other, testRecording())
	sc := newStatusClient(t, sp, c)

	require.NoError(t, sc.Remove(context.Background(), c))

	// Another partial profile still waits to be merged.
	require.True(t, recordingHasFinalizer(t, c))
}

func TestRemovePartialProfileIgnoresOtherNonPartialProfiles(t *testing.T) {
	t.Parallel()

	sp := recordedPartialProfile("test-profile")

	merged := recordedPartialProfile("merged-profile")
	merged.Finalizers = nil
	delete(merged.Labels, profilebase.ProfilePartialLabel)

	c := newFakeClient(t, sp.DeepCopy(), merged, testRecording())
	sc := newStatusClient(t, sp, c)

	require.NoError(t, sc.Remove(context.Background(), c))
	require.False(t, recordingHasFinalizer(t, c))
}

func TestRemovePartialProfileWithoutRecording(t *testing.T) {
	t.Parallel()

	sp := recordedPartialProfile("test-profile")
	c := newFakeClient(t, sp.DeepCopy())
	sc := newStatusClient(t, sp, c)

	// A recording that is already gone is not an error.
	require.NoError(t, sc.Remove(context.Background(), c))
}
