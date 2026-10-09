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

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeImage(t *testing.T) {
	t.Parallel()

	const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	for _, tc := range []struct {
		images []string
		want   string
	}{
		{
			images: []string{
				"nginx", "nginx:latest", "library/nginx", "docker.io/nginx",
				"docker.io/library/nginx:latest", "index.docker.io/library/nginx",
			},
			want: "index.docker.io/library/nginx:latest",
		},
		{
			images: []string{"nginx:1.23.2", "docker.io/library/nginx:1.23.2"},
			want:   "index.docker.io/library/nginx:1.23.2",
		},
		{
			images: []string{"user/app", "docker.io/user/app:latest"},
			want:   "index.docker.io/user/app:latest",
		},
		{
			images: []string{"quay.io/org/app", "quay.io/org/app:latest"},
			want:   "quay.io/org/app:latest",
		},
		{
			images: []string{"localhost:5000/app"},
			want:   "localhost:5000/app:latest",
		},
		{
			// The runtime pulls a reference with a tag and digest by digest.
			images: []string{"nginx@" + digest, "nginx:1.23.2@" + digest},
			want:   "index.docker.io/library/nginx@" + digest,
		},
		{
			// References which do not parse stay as they are.
			images: []string{"Invalid/Image"},
			want:   "Invalid/Image",
		},
	} {
		for _, image := range tc.images {
			require.Equal(t, tc.want, NormalizeImage(image), image)
		}
	}
}

func TestSameImage(t *testing.T) {
	t.Parallel()

	require.True(t, SameImage("nginx", "docker.io/library/nginx:latest"))
	require.True(t, SameImage("Invalid/Image", "Invalid/Image"))
	require.False(t, SameImage("nginx", "nginx:1.23.2"))
	require.False(t, SameImage("nginx", "quay.io/nginx"))
}
