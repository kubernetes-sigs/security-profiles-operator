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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	name := filepath.Join(dir, "profile.json")

	require.NoError(t, WriteFileAtomic(name, []byte("old"), 0o600))
	require.NoError(t, WriteFileAtomic(name, []byte("new"), 0o644))

	content, err := os.ReadFile(name)
	require.NoError(t, err)
	require.Equal(t, "new", string(content))

	info, err := os.Stat(name)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	// No temporary files are left behind.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	t.Parallel()

	name := filepath.Join(t.TempDir(), "missing", "profile.json")
	require.Error(t, WriteFileAtomic(name, []byte("data"), 0o600))
}

func TestWriteFileAtomicLongName(t *testing.T) {
	t.Parallel()

	name := filepath.Join(t.TempDir(), strings.Repeat("a", 250)+".json")
	require.NoError(t, WriteFileAtomic(name, []byte("data"), 0o600))
}
