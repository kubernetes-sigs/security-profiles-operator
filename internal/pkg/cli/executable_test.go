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

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExecutablePath verifies that an AppArmor profile attaches to the
// executable the command resolves to, like when it gets started.
func TestExecutablePath(t *testing.T) {
	t.Parallel()

	sh, err := exec.LookPath("sh")
	require.NoError(t, err)

	wantSh, err := filepath.Abs(sh)
	require.NoError(t, err)

	wantSh, err = filepath.EvalSymlinks(wantSh)
	require.NoError(t, err)

	got, err := ExecutablePath("sh")
	require.NoError(t, err)
	require.Equal(t, wantSh, got)

	// A symlink to the executable resolves to the executable.
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(sh, link))

	got, err = ExecutablePath(link)
	require.NoError(t, err)
	require.Equal(t, wantSh, got)

	wd, err := os.Getwd()
	require.NoError(t, err)

	for _, command := range []string{"./spoc-does-not-exist", "spoc-does-not-exist"} {
		got, err := ExecutablePath(command)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(wd, "spoc-does-not-exist"), got)
	}
}
