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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofile "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

// Expected shorten the node name if length exceed the limit.
func TestShortenNodeName(t *testing.T) {
	cases := []struct {
		name              string
		nodeName          string
		wantFinalizerName string
		profileBase       profilebase.SecurityProfileBase
	}{
		{
			name:              "NodeNameLongerThanLimit",
			nodeName:          "somenode-1234a-hhbhz-worker-c-xswffw.c.testlongnodename.internal",
			wantFinalizerName: "somenode-1234a-hhbhz-worker-c-xswffw.c.testlongnodename-deleted",
			profileBase:       regularSeccompProfile(),
		},
		{
			name:              "NodeNameShorterThanLimit",
			nodeName:          "somenode-1234a.internal",
			wantFinalizerName: "somenode-1234a.internal-deleted",
			profileBase:       regularSeccompProfile(),
		},
		{
			name:              "PartialProfile",
			nodeName:          "somenode-1234a.internal",
			wantFinalizerName: partialProfileFinalizer,
			profileBase:       partialSeccompProfile(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.NodeNameEnvKey, tc.nodeName)
			sc, err := NewForProfile(tc.profileBase, nil)
			require.NoError(t, err)

			require.Equal(t, tc.wantFinalizerName, sc.finalizerString)
		})
	}
}

func TestPerNodeStatusNameIncludesKind(t *testing.T) {
	cases := []struct {
		name           string
		nodeName       string
		profile        profilebase.SecurityProfileBase
		wantStatusName string
	}{
		{
			name:           "SeccompProfile",
			nodeName:       "worker-1",
			profile:        regularSeccompProfile(),
			wantStatusName: "seccompprofile-test-profile-worker-1",
		},
		{
			name:     "SelinuxProfile",
			nodeName: "worker-1",
			profile: &selinuxprofile.SelinuxProfile{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SelinuxProfile",
					APIVersion: "security-profiles-operator.x-k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile",
					Namespace: "test-namespace",
				},
			},
			wantStatusName: "selinuxprofile-test-profile-worker-1",
		},
		{
			name:           "LongNameGetsHashed",
			nodeName:       "very-long-node-name-that-exceeds-limits.example.com",
			profile:        regularSeccompProfile(),
			wantStatusName: "seccompprofile-8c3d274dad49d118a4e9b7f4c1e835d3c45a23de6c59aec5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.NodeNameEnvKey, tc.nodeName)
			sc, err := NewForProfile(tc.profile, nil)
			require.NoError(t, err)

			require.Equal(t, tc.wantStatusName, sc.perNodeStatusName())
		})
	}
}

func TestRemoveLegacyNodeStatus(t *testing.T) {
	t.Parallel()

	const nodeName = "worker-1"

	cases := []struct {
		name         string
		profile      profilebase.SecurityProfileBase
		mockGet      func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
		mockDelete   func(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error
		wantMigrated bool
	}{
		{
			name:    "LegacyStatusRemoved",
			profile: regularSeccompProfile(),
			mockGet: func(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if key.Name == "test-profile-"+nodeName {
					if ns, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
						ns.Labels = map[string]string{
							secprofnodestatusapi.StatusToProfLabel: util.KindBasedDNSLengthName(
								regularSeccompProfile(),
							),
						}
					}

					return nil
				}

				return kerrors.NewNotFound(schema.GroupResource{}, key.Name)
			},
			mockDelete: func(_ context.Context, _ client.Object, _ ...client.DeleteOption) error {
				return nil
			},
			wantMigrated: true,
		},
		{
			name:    "LegacyStatusNotFound",
			profile: regularSeccompProfile(),
			mockGet: func(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return kerrors.NewNotFound(schema.GroupResource{}, "")
			},
			wantMigrated: false,
		},
		{
			name:    "LegacyStatusWrongLabel",
			profile: regularSeccompProfile(),
			mockGet: func(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if key.Name == "test-profile-"+nodeName {
					if ns, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
						ns.Labels = map[string]string{
							secprofnodestatusapi.StatusToProfLabel: "different-owner",
						}
					}

					return nil
				}

				return kerrors.NewNotFound(schema.GroupResource{}, key.Name)
			},
			wantMigrated: false,
		},
		{
			name:    "GetError",
			profile: regularSeccompProfile(),
			mockGet: func(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errors.New("api server error")
			},
			wantMigrated: false,
		},
		{
			name:    "DeleteFailsReturnsNotMigrated",
			profile: regularSeccompProfile(),
			mockGet: func(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if key.Name == "test-profile-"+nodeName {
					if ns, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
						ns.Labels = map[string]string{
							secprofnodestatusapi.StatusToProfLabel: util.KindBasedDNSLengthName(
								regularSeccompProfile(),
							),
						}
					}

					return nil
				}

				return kerrors.NewNotFound(schema.GroupResource{}, key.Name)
			},
			mockDelete: func(_ context.Context, _ client.Object, _ ...client.DeleteOption) error {
				return errors.New("delete failed")
			},
			wantMigrated: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cl := &utiltest.MockClient{
				MockGet:    tc.mockGet,
				MockDelete: tc.mockDelete,
			}

			sc := &StatusClient{
				pol:      tc.profile,
				nodeName: nodeName,
				client:   cl,
				kind:     tc.profile.GetObjectKind().GroupVersionKind().Kind,
			}

			got, _ := sc.removeLegacyNodeStatus(context.Background())
			require.Equal(t, tc.wantMigrated, got)
		})
	}
}

// TestCreateAndRemoveWithClearedTypeMeta verifies that the node status name
// stays stable when the TypeMeta of the profile is empty or gets cleared, so
// that Remove deletes the same status object that Create made.
func TestCreateAndRemoveWithClearedTypeMeta(t *testing.T) {
	const nodeName = "worker-1"

	t.Setenv(config.NodeNameEnvKey, nodeName)

	scheme := runtime.NewScheme()
	require.NoError(t, seccompprofile.AddToScheme(scheme))
	require.NoError(t, secprofnodestatusapi.AddToScheme(scheme))

	clearTypeMeta := func(obj client.Object) {
		obj.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{})
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(regularSeccompProfile()).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
			) error {
				err := c.Update(ctx, obj, opts...)
				clearTypeMeta(obj)

				return err
			},
		}).
		Build()

	for _, withTypeMeta := range []bool{true, false} {
		pol := &seccompprofile.SeccompProfile{}
		key := client.ObjectKeyFromObject(regularSeccompProfile())
		require.NoError(t, cl.Get(t.Context(), key, pol))

		if !withTypeMeta {
			clearTypeMeta(pol)
		}

		sc, err := NewForProfile(pol, cl)
		require.NoError(t, err)

		_, err = sc.Create(t.Context())
		require.NoError(t, err)

		statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
		require.NoError(t, cl.List(t.Context(), statuses))
		require.Len(t, statuses.Items, 1)
		require.Equal(t, "seccompprofile-test-profile-worker-1", statuses.Items[0].Name)
		require.Equal(t, "SeccompProfile-test-profile",
			statuses.Items[0].Labels[secprofnodestatusapi.StatusToProfLabel])
		require.Equal(t, "SeccompProfile",
			statuses.Items[0].Labels[secprofnodestatusapi.StatusKindLabel])
		require.Equal(t, "SeccompProfile-test-profile",
			pol.GetLabels()[secprofnodestatusapi.StatusToProfLabel])

		exists, err := sc.Exists(t.Context())
		require.NoError(t, err)
		require.True(t, exists)

		require.NoError(t, sc.Remove(t.Context(), cl))
		require.NoError(t, cl.List(t.Context(), statuses))
		require.Empty(t, statuses.Items)

		// Drop the label so that the next iteration sets it again.
		require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(pol), pol))
		delete(pol.Labels, secprofnodestatusapi.StatusToProfLabel)
		require.NoError(t, cl.Update(t.Context(), pol))
	}
}

func regularSeccompProfile() *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SeccompProfile",
			APIVersion: "security-profiles-operator.x-k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
		},
	}
}

func partialSeccompProfile() *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SeccompProfile",
			APIVersion: "security-profiles-operator.x-k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
			Labels: map[string]string{
				profilebase.ProfilePartialLabel: "true",
			},
		},
	}
}
