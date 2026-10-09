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

package workloadannotator

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func TestSameActiveWorkloads(t *testing.T) {
	t.Parallel()

	require.True(t, sameActiveWorkloads(
		[]string{"namespace/pod-b", "namespace/pod-a"},
		[]string{"namespace/pod-a", "namespace/pod-b"},
	))
	require.False(t, sameActiveWorkloads(
		[]string{"namespace/pod-a"},
		[]string{"namespace/pod-a", "namespace/pod-b"},
	))
}

func newCountingReader(
	t *testing.T,
	testScheme *runtime.Scheme,
	object client.Object,
) (reader client.Reader, getCalls *int) {
	t.Helper()

	calls := 0
	countingReader := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(object).
		WithObjects(object).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context,
				c client.WithWatch,
				key client.ObjectKey,
				obj client.Object,
				opts ...client.GetOption,
			) error {
				calls++

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	return countingReader, &calls
}

// A profile which the cache shows with the current pods costs no read from
// the API server. If the cache was behind, the profile gets reconciled again
// once the cache has the update, see profileReconciler.
func TestUpdatePodReferencesSkipsReadForCachedNoOp(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		addToScheme func(*runtime.Scheme) error
		ownerKey    string
		profile     client.Object
		update      func(context.Context, *PodReconciler, client.Object) error
	}{
		{
			name:        "SeccompProfile",
			addToScheme: seccompprofileapi.AddToScheme,
			ownerKey:    spOwnerKey,
			profile: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
			},
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*seccompprofileapi.SeccompProfile)
				if !ok {
					return errors.New("object is not a SeccompProfile")
				}

				return r.updatePodReferencesForSeccomp(ctx, profile)
			},
		},
		{
			name:        "SelinuxProfile",
			addToScheme: selinuxprofileapi.AddToScheme,
			ownerKey:    seOwnerKey,
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
			},
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*selinuxprofileapi.SelinuxProfile)
				if !ok {
					return errors.New("object is not a SelinuxProfile")
				}

				return r.updatePodReferencesForSelinux(ctx, profile)
			},
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			testScheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(testScheme))
			require.NoError(t, testCase.addToScheme(testScheme))

			apiReader, readerGetCalls := newCountingReader(t, testScheme, testCase.profile)
			fakeClient := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithStatusSubresource(testCase.profile).
				WithObjects(testCase.profile).
				WithIndex(&corev1.Pod{}, testCase.ownerKey, func(client.Object) []string { return nil }).
				Build()

			r := &PodReconciler{client: fakeClient, reader: apiReader}
			require.NoError(t, testCase.update(ctx, r, testCase.profile))
			require.Zero(t, *readerGetCalls)
		})
	}
}

func TestUpdatePodReferencesForSeccompIgnoresDeletedProfile(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(testScheme))
	require.NoError(t, seccompprofileapi.AddToScheme(testScheme))

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-profile",
			Finalizers: []string{util.HasActivePodsFinalizerString},
		},
	}
	apiReader := fake.NewClientBuilder().WithScheme(testScheme).Build()

	writes := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithIndex(&corev1.Pod{}, spOwnerKey, func(client.Object) []string { return nil }).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
			) error {
				writes++

				return c.Update(ctx, obj, opts...)
			},
			SubResourcePatch: func(
				ctx context.Context, c client.Client, sub string, obj client.Object,
				patch client.Patch, opts ...client.SubResourcePatchOption,
			) error {
				writes++

				return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	r := &PodReconciler{client: fakeClient, reader: apiReader}
	require.NoError(t, r.updatePodReferencesForSeccomp(ctx, profile))

	// The deleted profile is neither updated nor recreated.
	require.Zero(t, writes)

	key := client.ObjectKeyFromObject(profile)
	err := fakeClient.Get(ctx, key, &seccompprofileapi.SeccompProfile{})
	require.True(t, kerrors.IsNotFound(err))
}

func TestUpdatePodReferencesIgnoresDeletionBeforeFinalizerUpdate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		profile          client.Object
		ownerKey         string
		profileReference string
		update           func(context.Context, *PodReconciler, client.Object) error
	}{
		{
			name: "SeccompProfile",
			profile: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
				Status: seccompprofileapi.SeccompProfileStatus{
					ActiveWorkloads:      []string{"example/pod"},
					ActiveWorkloadsCount: 1,
				},
			},
			ownerKey:         spOwnerKey,
			profileReference: "operator/test-profile.json",
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*seccompprofileapi.SeccompProfile)
				if !ok {
					return errors.New("object is not a SeccompProfile")
				}

				return r.updatePodReferencesForSeccomp(ctx, profile)
			},
		},
		{
			name: "SelinuxProfile",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
				Status: selinuxprofileapi.SelinuxProfileStatus{
					ActiveWorkloads:      []string{"example/pod"},
					ActiveWorkloadsCount: 1,
				},
			},
			ownerKey:         seOwnerKey,
			profileReference: "test-profile.process",
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*selinuxprofileapi.SelinuxProfile)
				if !ok {
					return errors.New("object is not a SelinuxProfile")
				}

				return r.updatePodReferencesForSelinux(ctx, profile)
			},
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			testScheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(testScheme))
			require.NoError(t, seccompprofileapi.AddToScheme(testScheme))
			require.NoError(t, selinuxprofileapi.AddToScheme(testScheme))

			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "example", Name: "pod"}}
			apiReader := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithStatusSubresource(testCase.profile).
				WithObjects(testCase.profile).
				Build()
			fakeClient := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(pod).
				WithIndex(&corev1.Pod{}, testCase.ownerKey, func(client.Object) []string {
					return []string{testCase.profileReference}
				}).
				Build()

			r := &PodReconciler{client: fakeClient, reader: apiReader}
			require.NoError(t, testCase.update(ctx, r, testCase.profile))
		})
	}
}

func TestUpdatePodReferencesIgnoresDeletionBeforeFinalizerRemoval(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		profile  client.Object
		ownerKey string
		update   func(context.Context, *PodReconciler, client.Object) error
	}{
		{
			name: "SeccompProfile",
			profile: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-profile",
					Finalizers: []string{util.HasActivePodsFinalizerString},
				},
			},
			ownerKey: spOwnerKey,
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*seccompprofileapi.SeccompProfile)
				if !ok {
					return errors.New("object is not a SeccompProfile")
				}

				return r.updatePodReferencesForSeccomp(ctx, profile)
			},
		},
		{
			name: "SelinuxProfile",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-profile",
					Finalizers: []string{util.HasActivePodsFinalizerString},
				},
			},
			ownerKey: seOwnerKey,
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*selinuxprofileapi.SelinuxProfile)
				if !ok {
					return errors.New("object is not a SelinuxProfile")
				}

				return r.updatePodReferencesForSelinux(ctx, profile)
			},
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			testScheme := runtime.NewScheme()
			require.NoError(t, corev1.AddToScheme(testScheme))
			require.NoError(t, seccompprofileapi.AddToScheme(testScheme))
			require.NoError(t, selinuxprofileapi.AddToScheme(testScheme))

			apiReader := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithStatusSubresource(testCase.profile).
				WithObjects(testCase.profile).
				Build()
			fakeClient := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithIndex(&corev1.Pod{}, testCase.ownerKey, func(client.Object) []string { return nil }).
				Build()

			r := &PodReconciler{client: fakeClient, reader: apiReader}
			require.NoError(t, testCase.update(ctx, r, testCase.profile))
		})
	}
}

func TestUpdatePodReferencesForSelinuxSkipsEquivalentStatusUpdate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(testScheme))
	require.NoError(t, selinuxprofileapi.AddToScheme(testScheme))

	stored := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
		Status: selinuxprofileapi.SelinuxProfileStatus{
			ActiveWorkloads:      []string{"example/pod-b", "example/pod-a"},
			ActiveWorkloadsCount: 2,
		},
	}
	podA := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "example", Name: "pod-a"}}
	podB := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "example", Name: "pod-b"}}
	apiReader := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(stored).
		WithObjects(stored).
		Build()

	statusUpdateCalls := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(stored).
		WithObjects(stored, podA, podB).
		WithIndex(&corev1.Pod{}, seOwnerKey, func(client.Object) []string {
			return []string{stored.GetPolicyUsage()}
		}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context,
				c client.Client,
				subresource string,
				obj client.Object,
				patch client.Patch,
				opts ...client.SubResourcePatchOption,
			) error {
				statusUpdateCalls++

				return c.SubResource(subresource).Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	r := &PodReconciler{client: fakeClient, reader: apiReader}
	require.NoError(t, r.updatePodReferencesForSelinux(ctx, stored.DeepCopy()))
	require.Zero(t, statusUpdateCalls)
}

func TestGetSeccompProfilesFromPod(t *testing.T) {
	t.Parallel()

	profilePath := "operator/test.json"
	profilePath2 := "operator/test2.json"
	cases := []struct {
		name string
		pod  corev1.Pod
		want []string
	}{
		{
			name: "SeccompProfileForPod",
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type:             "Localhost",
							LocalhostProfile: &profilePath,
						},
					},
				},
			},
			want: []string{profilePath},
		},
		{
			name: "SeccompProfileForOneContainer",
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "container1",
						Image: "testimage",
						SecurityContext: &corev1.SecurityContext{
							SeccompProfile: &corev1.SeccompProfile{
								Type:             "Localhost",
								LocalhostProfile: &profilePath,
							},
						},
					}},
				},
			},
			want: []string{profilePath},
		},
		{
			name: "SeccompProfileForMultipleContainers",
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container1",
							Image: "testimage",
							SecurityContext: &corev1.SecurityContext{
								SeccompProfile: &corev1.SeccompProfile{
									Type:             "Localhost",
									LocalhostProfile: &profilePath,
								},
							},
						},
						{
							Name:  "container2",
							Image: "testimage2",
							SecurityContext: &corev1.SecurityContext{
								SeccompProfile: &corev1.SeccompProfile{
									Type:             "Localhost",
									LocalhostProfile: &profilePath2,
								},
							},
						},
					},
				},
			},
			want: []string{profilePath, profilePath2},
		},
		{
			name: "SeccompProfileInAnnotation",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						corev1.SeccompPodAnnotationKey: "localhost/" + profilePath,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
				},
			},
			want: []string{profilePath},
		},
		{
			name: "SeccompProfileRuntimeDefaultForPod",
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type: "RuntimeDefault",
						},
					},
				},
			},
			want: []string{},
		},
		{
			name: "SeccompProfileLocalhostNoSlash",
			pod: corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type:             "Localhost",
							LocalhostProfile: &[]string{"mariadb-seccomp-profile.json"}[0],
						},
					},
				},
			},
			want: []string{},
		},
		{
			name: "SeccompProfileInAnnotationNoSlash",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						corev1.SeccompPodAnnotationKey: "localhost/mariadb-seccomp-profile.json",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
				},
			},
			want: []string{},
		},
		{
			name: "SeccompProfileInPodAndContainerAndAnnotation",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						corev1.SeccompPodAnnotationKey: "localhost/" + profilePath,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "container1",
							Image: "testimage",
							SecurityContext: &corev1.SecurityContext{
								SeccompProfile: &corev1.SeccompProfile{
									Type:             "Localhost",
									LocalhostProfile: &profilePath2,
								},
							},
						},
						{
							Name:  "container2",
							Image: "testimage2",
						},
					},
					SecurityContext: &corev1.PodSecurityContext{
						SeccompProfile: &corev1.SeccompProfile{
							Type:             "Localhost",
							LocalhostProfile: &profilePath,
						},
					},
				},
			},
			want: []string{profilePath, profilePath2},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := getSeccompProfilesFromPod(&tc.pod)
			require.Equal(t, tc.want, got)
		})
	}

	badPod := corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type:             "Localhost",
					LocalhostProfile: nil,
				},
			},
		},
	}
	badCases := []struct {
		name    string
		profile string
	}{
		{
			name:    "NoSuffix",
			profile: "operator/test",
		},
		{
			name:    "BadSuffix",
			profile: "operator/test.js",
		},
		{
			name:    "WrongPath",
			profile: "foo/bar/baz",
		},
		{
			name:    "NotLocalhostPath",
			profile: "runtime/default",
		},
	}

	for _, tc := range badCases {
		badPod.Spec.SecurityContext.SeccompProfile.LocalhostProfile = &tc.profile
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := getSeccompProfilesFromPod(&badPod)
			require.Equal(t, []string{}, got)
		})
	}
}

func TestActiveWorkloadRequests(t *testing.T) {
	t.Parallel()

	want := []reconcile.Request{
		{NamespacedName: client.ObjectKey{Namespace: "default", Name: "pod-a"}},
		{NamespacedName: client.ObjectKey{Namespace: "other", Name: "pod-b"}},
	}
	workloads := []string{"default/pod-a", "invalid", "other/pod-b"}

	sp := &seccompprofileapi.SeccompProfile{}
	sp.Status.ActiveWorkloads = workloads
	require.Equal(t, want, activeWorkloadRequests(t.Context(), sp))

	se := &selinuxprofileapi.SelinuxProfile{}
	se.Status.ActiveWorkloads = workloads
	require.Equal(t, want, activeWorkloadRequests(t.Context(), se))

	raw := &selinuxprofileapi.RawSelinuxProfile{}
	raw.Status.ActiveWorkloads = workloads
	require.Equal(t, want, activeWorkloadRequests(t.Context(), raw))

	aa := &apparmorprofileapi.AppArmorProfile{}
	aa.Status.ActiveWorkloads = workloads
	require.Equal(t, want, activeWorkloadRequests(t.Context(), aa))

	require.Empty(t, activeWorkloadRequests(t.Context(), &corev1.Pod{}))
}
