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

package selinuxprofile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsSystemSELinuxModule(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T, modules ...string) string {
		t.Helper()

		store := t.TempDir()
		modulesDir := filepath.Join(store, "targeted", "active", "modules", "100")
		require.NoError(t, os.MkdirAll(modulesDir, 0o755))

		for _, m := range modules {
			require.NoError(t, os.Mkdir(filepath.Join(modulesDir, m), 0o755))
		}

		return store
	}

	cases := []struct {
		name    string
		modules []string
		query   string
		want    bool
	}{
		{
			name:    "system module kerberos is detected",
			modules: []string{"kerberos", "container"},
			query:   "kerberos",
			want:    true,
		},
		{
			name:    "system module container is detected",
			modules: []string{"kerberos", "container"},
			query:   "container",
			want:    true,
		},
		{
			name:    "custom name does not conflict",
			modules: []string{"kerberos", "container"},
			query:   "my-custom-profile",
			want:    false,
		},
		{
			name:    "prefixed name does not conflict",
			modules: []string{"kerberos"},
			query:   "custom-kerberos",
			want:    false,
		},
		{
			name:    "empty module store",
			modules: nil,
			query:   "kerberos",
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := setup(t, tc.modules...)
			got := isSystemSELinuxModule(store, tc.query)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestIsSystemSELinuxModuleNonexistentPath(t *testing.T) {
	t.Parallel()

	got := isSystemSELinuxModule("/nonexistent/path", "kerberos")
	require.False(t, got)
}
