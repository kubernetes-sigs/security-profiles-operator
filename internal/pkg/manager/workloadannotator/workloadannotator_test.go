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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
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

func TestUpdatePodReferencesForSeccompRefreshesBeforeNoOpCheck(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testScheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(testScheme))
	require.NoError(t, seccompprofileapi.AddToScheme(testScheme))

	stored := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
		Status: seccompprofileapi.SeccompProfileStatus{
			ActiveWorkloads: []string{"example/pod-a"},
		},
	}
	stale := stored.DeepCopy()
	stale.Status.ActiveWorkloads = nil

	readerGetCalls := 0
	apiReader := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(stored).
		WithObjects(stored).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context,
				c client.WithWatch,
				key client.ObjectKey,
				obj client.Object,
				opts ...client.GetOption,
			) error {
				readerGetCalls++

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(stored).
		WithObjects(stored).
		WithIndex(&corev1.Pod{}, spOwnerKey, func(client.Object) []string { return nil }).
		Build()

	r := &PodReconciler{client: fakeClient, reader: apiReader}
	require.NoError(t, r.updatePodReferencesForSeccomp(ctx, stale))
	require.Equal(t, 1, readerGetCalls)

	updated := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, fakeClient.Get(ctx, client.ObjectKey{Name: stored.Name}, updated))
	require.Empty(t, updated.Status.ActiveWorkloads)
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
