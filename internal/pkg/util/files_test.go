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
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestRemoveStaleTempFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)

	write := func(name string, modTime time.Time) string {
		t.Helper()

		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("data"), 0o600))
		require.NoError(t, os.Chtimes(p, modTime, modTime))

		return p
	}

	// A leftover of an interrupted WriteFileAtomic.
	stale := write(tempFilePrefix+rand.Text(), old)
	// A file which may still be written concurrently.
	fresh := write(tempFilePrefix+rand.Text(), time.Now())
	// Files which only look similar are not ours.
	keep := []string{
		write("profile.json", old),
		write(".tmp-profile.json", old),
		write(tempFilePrefix+strings.ToLower(rand.Text()), old),
		write(tempFilePrefix+rand.Text()+".json", old),
	}

	// A directory with a matching name is not ours either.
	dirName := filepath.Join(dir, tempFilePrefix+rand.Text())
	require.NoError(t, os.Mkdir(dirName, 0o700))
	require.NoError(t, os.Chtimes(dirName, old, old))

	removed, err := RemoveStaleTempFiles(dir, time.Minute)
	require.NoError(t, err)
	require.Equal(t, []string{stale}, removed)

	require.NoFileExists(t, stale)
	require.FileExists(t, fresh)

	for _, p := range keep {
		require.FileExists(t, p)
	}

	require.DirExists(t, dirName)
}

func TestRemoveStaleTempFilesMissingDir(t *testing.T) {
	t.Parallel()

	removed, err := RemoveStaleTempFiles(filepath.Join(t.TempDir(), "missing"), time.Minute)
	require.NoError(t, err)
	require.Empty(t, removed)
}
