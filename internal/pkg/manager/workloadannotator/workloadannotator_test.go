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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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

//nolint:dupl // Seccomp and SELinux profiles intentionally exercise the same reconciliation contract.
func TestUpdatePodReferencesRefreshesBeforeNoOpCheck(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		addToScheme  func(*runtime.Scheme) error
		ownerKey     string
		profiles     func() (client.Object, client.Object)
		update       func(context.Context, *PodReconciler, client.Object) error
		assertStatus func(*testing.T, context.Context, client.Client)
	}{
		{
			name:        "SeccompProfile",
			addToScheme: seccompprofileapi.AddToScheme,
			ownerKey:    spOwnerKey,
			profiles: func() (client.Object, client.Object) {
				stored := &seccompprofileapi.SeccompProfile{
					ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
					Status: seccompprofileapi.SeccompProfileStatus{
						ActiveWorkloads: []string{"example/pod-a"},
					},
				}
				stale := stored.DeepCopy()
				stale.Status.ActiveWorkloads = nil

				return stored, stale
			},
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*seccompprofileapi.SeccompProfile)
				if !ok {
					return errors.New("object is not a SeccompProfile")
				}

				return r.updatePodReferencesForSeccomp(ctx, profile)
			},
			assertStatus: func(t *testing.T, ctx context.Context, c client.Client) {
				t.Helper()

				updated := &seccompprofileapi.SeccompProfile{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "test-profile"}, updated))
				require.Empty(t, updated.Status.ActiveWorkloads)
			},
		},
		{
			name:        "SelinuxProfile",
			addToScheme: selinuxprofileapi.AddToScheme,
			ownerKey:    seOwnerKey,
			profiles: func() (client.Object, client.Object) {
				stored := &selinuxprofileapi.SelinuxProfile{
					ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
					Status: selinuxprofileapi.SelinuxProfileStatus{
						ActiveWorkloads: []string{"example/pod-a"},
					},
				}
				stale := stored.DeepCopy()
				stale.Status.ActiveWorkloads = nil

				return stored, stale
			},
			update: func(ctx context.Context, r *PodReconciler, object client.Object) error {
				profile, ok := object.(*selinuxprofileapi.SelinuxProfile)
				if !ok {
					return errors.New("object is not a SelinuxProfile")
				}

				return r.updatePodReferencesForSelinux(ctx, profile)
			},
			assertStatus: func(t *testing.T, ctx context.Context, c client.Client) {
				t.Helper()

				updated := &selinuxprofileapi.SelinuxProfile{}
				require.NoError(t, c.Get(ctx, client.ObjectKey{Name: "test-profile"}, updated))
				require.Empty(t, updated.Status.ActiveWorkloads)
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

			stored, stale := testCase.profiles()
			apiReader, readerGetCalls := newCountingReader(t, testScheme, stored)
			fakeClient := fake.NewClientBuilder().
				WithScheme(testScheme).
				WithStatusSubresource(stored).
				WithObjects(stored).
				WithIndex(&corev1.Pod{}, testCase.ownerKey, func(client.Object) []string { return nil }).
				Build()

			r := &PodReconciler{client: fakeClient, reader: apiReader}
			require.NoError(t, testCase.update(ctx, r, stale))
			require.Equal(t, 1, *readerGetCalls)
			testCase.assertStatus(t, ctx, fakeClient)
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
	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithIndex(&corev1.Pod{}, spOwnerKey, func(client.Object) []string { return nil }).
		Build()

	r := &PodReconciler{client: fakeClient, reader: apiReader}
	require.NoError(t, r.updatePodReferencesForSeccomp(ctx, profile))
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
			ActiveWorkloads: []string{"example/pod-b", "example/pod-a"},
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
			SubResourceUpdate: func(
				ctx context.Context,
				c client.Client,
				subresource string,
				obj client.Object,
				opts ...client.SubResourceUpdateOption,
			) error {
				statusUpdateCalls++

				return c.SubResource(subresource).Update(ctx, obj, opts...)
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
