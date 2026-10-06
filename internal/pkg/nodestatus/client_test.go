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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const testNode = "worker-1"

// newFakeClient returns a fake client that, like the cache backed client of
// the manager, returns objects with their type meta set. The status client
// derives the status names from the kind of the profile.
func newFakeClient(t *testing.T, objs ...client.Object) client.WithWatch {
	t.Helper()

	scheme := utiltest.NewScheme(t)

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

func TestStatusObjLabelsValidForLongNodeName(t *testing.T) {
	t.Parallel()

	for _, node := range []string{
		testNode,
		strings.Repeat("n", validation.LabelValueMaxLength),
		strings.Repeat("n", validation.LabelValueMaxLength+1),
		strings.Repeat("a", 40) + "." + strings.Repeat("b", 200),
	} {
		sc, err := NewForProfileOnNode(preparedProfile(), nil, node)
		require.NoError(t, err)

		status := sc.statusObj(secprofnodestatusapi.ProfileStateInstalled)
		for key, value := range status.Labels {
			require.Empty(t, validation.IsValidLabelValue(value), "label %s=%s", key, value)
		}

		// The spec keeps the full node name.
		require.Equal(t, node, status.Spec.NodeName)

		if len(node) <= validation.LabelValueMaxLength {
			require.Equal(t, node, status.Labels[secprofnodestatusapi.StatusToNodeLabel])
		}
	}

	// Long node names that only differ after the kept prefix get different
	// label values.
	first, err := NewForProfileOnNode(preparedProfile(), nil, strings.Repeat("n", 80)+"1")
	require.NoError(t, err)
	second, err := NewForProfileOnNode(preparedProfile(), nil, strings.Repeat("n", 80)+"2")
	require.NoError(t, err)
	require.NotEqual(t,
		first.statusObj("").Labels[secprofnodestatusapi.StatusToNodeLabel],
		second.statusObj("").Labels[secprofnodestatusapi.StatusToNodeLabel],
	)
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
		Status: secprofnodestatusapi.SecurityProfileNodeStatusStatus{
			Status: secprofnodestatusapi.ProfileStateInstalled,
		},
	}

	c := newFakeClient(t, sp.DeepCopy(), legacy)
	sc := newStatusClient(t, sp, c)

	migrated, err := sc.Create(context.Background())
	require.NoError(t, err)
	require.True(t, migrated)

	_, err = nodeStatus(t, c, legacy.Name)
	require.True(t, kerrors.IsNotFound(err))

	// The migrated status keeps the state of the legacy one.
	status, err := nodeStatus(t, c, wantStatusName)
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, status.Status.Status)

	state, err := sc.State(context.Background())
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, state)
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

func TestRemovePartialProfileKeepsRecordingFinalizer(t *testing.T) {
	t.Parallel()

	// The recording has partial profiles of two kinds. Removing the last
	// partial seccomp profile from the node must not release the recording,
	// because the partial AppArmor profile still waits to be merged. Only the
	// recording merger of the manager, which checks every kind, releases it.
	sp := recordedPartialProfile("test-profile")
	aa := &apparmorprofileapi.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "other-profile",
			Finalizers: []string{partialProfileFinalizer},
			Labels:     sp.Labels,
		},
	}
	c := newFakeClient(t, sp.DeepCopy(), aa, testRecording())
	sc := newStatusClient(t, sp, c)

	require.NoError(t, sc.Remove(context.Background(), c))
	require.True(t, recordingHasFinalizer(t, c))
	require.NotContains(t, storedProfile(t, c, sp.Name).Finalizers, partialProfileFinalizer)
}

func TestRemovePartialProfileWithoutRecording(t *testing.T) {
	t.Parallel()

	sp := recordedPartialProfile("test-profile")
	c := newFakeClient(t, sp.DeepCopy())
	sc := newStatusClient(t, sp, c)

	// A recording that is already gone is not an error.
	require.NoError(t, sc.Remove(context.Background(), c))
}

func TestCreatePolLabelPersistsAfterConflict(t *testing.T) {
	t.Parallel()

	sp := regularSeccompProfile()
	base := newFakeClient(t, sp.DeepCopy())
	conflicts := 0

	// The first label update fails with a conflict, like it does when many
	// daemons add their finalizers at once.
	c := interceptor.NewClient(base, interceptor.Funcs{
		Update: func(
			ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			if _, ok := obj.GetLabels()[secprofnodestatusapi.StatusToProfLabel]; ok &&
				conflicts == 0 {
				conflicts++

				return kerrors.NewConflict(
					seccompprofile.GroupVersion.WithResource("seccompprofiles").GroupResource(),
					obj.GetName(), nil,
				)
			}

			return cl.Update(ctx, obj, opts...)
		},
	})

	sc := newStatusClient(t, sp, c)
	require.NoError(t, sc.createPolLabel(context.Background()))
	require.Equal(t, 1, conflicts)
	require.Equal(t,
		sc.profileID(),
		storedProfile(t, base, sp.GetName()).Labels[secprofnodestatusapi.StatusToProfLabel],
	)
}

func TestSetNodeStatusSkipsUnchangedStatus(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	existing := newStatusClient(t, sp, nil).statusObj(secprofnodestatusapi.ProfileStateInstalled)
	base := newFakeClient(t, sp.DeepCopy(), existing)
	updates := 0

	c := interceptor.NewClient(base, interceptor.Funcs{
		Update: func(
			ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			updates++

			return cl.Update(ctx, obj, opts...)
		},
		SubResourceUpdate: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption,
		) error {
			updates++

			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	})

	sc := newStatusClient(t, sp, c)
	require.NoError(
		t,
		sc.SetNodeStatus(context.Background(), secprofnodestatusapi.ProfileStateInstalled),
	)
	require.Zero(t, updates)
}

// conflictOnce returns a client which fails the first update of the objects
// which match with a conflict, like the API server does when another writer
// got there first.
func conflictOnce(
	base client.WithWatch, match func(client.Object) bool,
) (c client.WithWatch, conflicts *int) {
	conflicts = new(int)

	return interceptor.NewClient(base, interceptor.Funcs{
		Update: func(
			ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			if match(obj) && *conflicts == 0 {
				(*conflicts)++

				return kerrors.NewConflict(
					schema.GroupResource{Resource: "objects"}, obj.GetName(), nil,
				)
			}

			return cl.Update(ctx, obj, opts...)
		},
	}), conflicts
}

func TestSetAnnotationRetriesOnConflict(t *testing.T) {
	t.Parallel()

	sp := preparedProfile()
	existing := newStatusClient(t, sp, nil).statusObj(secprofnodestatusapi.ProfileStatePending)
	base := newFakeClient(t, sp.DeepCopy(), existing)

	c, conflicts := conflictOnce(base, func(obj client.Object) bool {
		_, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus)

		return ok
	})

	sc := newStatusClient(t, sp, c)
	require.NoError(t, sc.SetAnnotation(context.Background(), "key", "value"))
	require.Equal(t, 1, *conflicts)

	status, err := nodeStatus(t, base, wantStatusName)
	require.NoError(t, err)
	require.Equal(t, "value", status.Annotations["key"])
}

// A node whose name does not fit into a finalizer used to get a truncated
// one, which it could share with another node. The daemon adds the hashed form
// next to it and keeps handling profiles which only carry the old one.
func TestLegacyNodeFinalizer(t *testing.T) {
	t.Parallel()

	longNode := strings.Repeat("n", 100)
	current := util.GetFinalizerNodeString(longNode)
	legacy := util.GetLegacyFinalizerNodeString(longNode)
	require.NotEmpty(t, legacy)
	require.NotEqual(t, current, legacy)

	newClient := func(t *testing.T, sp *seccompprofile.SeccompProfile, c client.Client) *StatusClient {
		t.Helper()

		sc, err := NewForProfileOnNode(sp, c, longNode)
		require.NoError(t, err)
		require.Equal(t, current, sc.finalizerString)
		require.Equal(t, legacy, sc.legacyFinalizerString)

		return sc
	}

	t.Run("the legacy finalizer counts as present", func(t *testing.T) {
		t.Parallel()

		sp := regularSeccompProfile()
		sp.Finalizers = []string{legacy}

		require.True(t, newClient(t, sp, newFakeClient(t)).FinalizerExists())
		require.False(t, newClient(t, regularSeccompProfile(), newFakeClient(t)).FinalizerExists())
	})

	t.Run("creating the status keeps the legacy finalizer", func(t *testing.T) {
		t.Parallel()

		sp := regularSeccompProfile()
		sp.Finalizers = []string{"other", legacy}
		c := newFakeClient(t, sp.DeepCopy())

		_, err := newClient(t, sp, c).Create(context.Background())
		require.NoError(t, err)
		require.ElementsMatch(t,
			[]string{"other", legacy, current},
			storedProfile(t, c, sp.Name).Finalizers,
		)
	})

	t.Run("removing the status strips both forms", func(t *testing.T) {
		t.Parallel()

		sp := regularSeccompProfile()
		sp.Finalizers = []string{"other", legacy, current}
		c := newFakeClient(t, sp.DeepCopy())

		require.NoError(t, newClient(t, sp, c).Remove(context.Background(), c))
		require.Equal(t, []string{"other"}, storedProfile(t, c, sp.Name).Finalizers)
	})

	t.Run("an existing profile gets migrated", func(t *testing.T) {
		t.Parallel()

		sp := regularSeccompProfile()
		sp.Finalizers = []string{"other", legacy}
		c := newFakeClient(t, sp.DeepCopy())
		sc := newClient(t, sp, c)

		require.NoError(t, sc.MigrateLegacyFinalizer(context.Background()))
		require.ElementsMatch(t,
			[]string{"other", legacy, current},
			storedProfile(t, c, sp.Name).Finalizers,
		)

		// Nothing is left to migrate.
		version := storedProfile(t, c, sp.Name).ResourceVersion
		require.NoError(t, sc.MigrateLegacyFinalizer(context.Background()))
		require.Equal(t, version, storedProfile(t, c, sp.Name).ResourceVersion)
	})

	t.Run("the legacy finalizer shared with another node", func(t *testing.T) {
		t.Parallel()

		// Both names share the truncated prefix of the legacy finalizer.
		nodeA := strings.Repeat("n", 99) + "a"
		nodeB := strings.Repeat("n", 99) + "b"

		require.Equal(t, legacy, util.GetLegacyFinalizerNodeString(nodeA))
		require.Equal(t, legacy, util.GetLegacyFinalizerNodeString(nodeB))

		currentA := util.GetFinalizerNodeString(nodeA)
		currentB := util.GetFinalizerNodeString(nodeB)
		require.NotEqual(t, currentA, currentB)

		sp := regularSeccompProfile()
		sp.Finalizers = []string{"other", legacy}
		c := newFakeClient(t, sp.DeepCopy())

		scA, err := NewForProfileOnNode(sp, c, nodeA)
		require.NoError(t, err)

		// Node B has not migrated yet and relies on the legacy finalizer,
		// so migrating node A keeps it.
		require.NoError(t, scA.MigrateLegacyFinalizer(context.Background()))
		require.ElementsMatch(t,
			[]string{"other", legacy, currentA},
			storedProfile(t, c, sp.Name).Finalizers,
		)

		scB, err := NewForProfileOnNode(storedProfile(t, c, sp.Name), c, nodeB)
		require.NoError(t, err)
		require.True(t, scB.FinalizerExists())

		// Removing the profile from node A strips its own and the legacy
		// finalizer, as in earlier releases, see MigrateLegacyFinalizer.
		require.NoError(t, scA.Remove(context.Background(), c))
		require.Equal(t, []string{"other"}, storedProfile(t, c, sp.Name).Finalizers)
	})

	t.Run("a partial profile has no legacy finalizer", func(t *testing.T) {
		t.Parallel()

		sc, err := NewForProfileOnNode(
			recordedPartialProfile("partial"),
			newFakeClient(t),
			longNode,
		)
		require.NoError(t, err)
		require.Equal(t, partialProfileFinalizer, sc.finalizerString)
		require.Empty(t, sc.legacyFinalizerString)
	})
}
