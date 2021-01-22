/*
Copyright 2021 The Kubernetes Authors.

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

package binding

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestNewContainerMap(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		podSpec *corev1.PodSpec
		want    containerMap
	}{
		{
			name:    "NoContainers",
			podSpec: &corev1.PodSpec{},
			want:    map[string][]*corev1.Container{},
		},
		{
			name: "OnlyContainers",
			podSpec: &corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "web",
						Image: "nginx",
					},
					{
						Name:  "sidecar",
						Image: "sidecar-image",
					},
				},
			},
			want: map[string][]*corev1.Container{
				"nginx": {
					{
						Name:  "web",
						Image: "nginx",
					},
				},
				"sidecar-image": {
					{
						Name:  "sidecar",
						Image: "sidecar-image",
					},
				},
			},
		},
		{
			name: "OnlyInitContainers",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{
					{
						Name:  "step1",
						Image: "busybox",
					},
					{
						Name:  "step2",
						Image: "bash",
					},
				},
			},
			want: map[string][]*corev1.Container{
				"busybox": {
					{
						Name:  "step1",
						Image: "busybox",
					},
				},
				"bash": {
					{
						Name:  "step2",
						Image: "bash",
					},
				},
			},
		},
		{
			name: "ContainersAndInitContainers",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name:  "init",
					Image: "bash",
				}},
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "nginx",
				}},
			},
			want: map[string][]*corev1.Container{
				"bash": {
					{
						Name:  "init",
						Image: "bash",
					},
				},
				"nginx": {
					{
						Name:  "app",
						Image: "nginx",
					},
				},
			},
		},
		{
			name: "DuplicateImages",
			podSpec: &corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name:  "init",
					Image: "bash",
				}},
				Containers: []corev1.Container{{
					Name:  "app",
					Image: "bash",
				}},
			},
			want: map[string][]*corev1.Container{
				"bash": {
					{
						Name:  "app",
						Image: "bash",
					},
					{
						Name:  "init",
						Image: "bash",
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := newContainerMap(tc.podSpec)
			for k, v := range result {
				require.Equal(t, tc.want[k], v)
			}
		})
	}
}
