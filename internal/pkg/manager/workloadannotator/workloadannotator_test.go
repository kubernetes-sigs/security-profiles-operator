/*
Copyright 2020 The Kubernetes Authors.

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
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetSeccompProfilesFromPod(t *testing.T) {
	t.Parallel()

	profilePath := "operator/default/test.json"
	profilePath2 := "operator/default/test2.json"
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
					Annotations: map[string]string{corev1.SeccompPodAnnotationKey: "localhost/" + profilePath},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "container1", Image: "testimage"}},
				},
			},
			want: []string{profilePath},
		},
		{
			name: "SeccompProfileInPodAndContainerAndAnnotation",
			pod: corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{corev1.SeccompPodAnnotationKey: "localhost/" + profilePath},
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
		tc := tc
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
			profile: "operator/default/test",
		},
		{
			name:    "BadSuffix",
			profile: "operator/default/test.js",
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
		tc := tc
		badPod.Spec.SecurityContext.SeccompProfile.LocalhostProfile = &tc.profile
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := getSeccompProfilesFromPod(&badPod)
			require.Equal(t, []string{}, got)
		})
	}
}
