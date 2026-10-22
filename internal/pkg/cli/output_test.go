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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWriteFileStdoutAppends verifies that the output to stdout goes there as
// it is, so that a file stdout gets appended to is not truncated.
//
//nolint:paralleltest // replaces os.Stdout
func TestWriteFileStdoutAppends(t *testing.T) {
	name := filepath.Join(t.TempDir(), "out")
	require.NoError(t, os.WriteFile(name, []byte("first\n"), 0o600))

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)

	stdout := os.Stdout
	os.Stdout = file

	t.Cleanup(func() { os.Stdout = stdout })

	require.NoError(t, WriteFile(Stdout, []byte("second\n"), 0o644))
	require.NoError(t, file.Close())

	content, err := os.ReadFile(name)
	require.NoError(t, err)
	require.Equal(t, "first\nsecond\n", string(content))
}

func TestWriteFile(t *testing.T) {
	t.Parallel()

	name := filepath.Join(t.TempDir(), "out")
	require.NoError(t, os.WriteFile(name, []byte("old content\n"), 0o600))

	require.NoError(t, WriteFile(name, []byte("new\n"), 0o644))

	content, err := os.ReadFile(name)
	require.NoError(t, err)
	require.Equal(t, "new\n", string(content))
}
