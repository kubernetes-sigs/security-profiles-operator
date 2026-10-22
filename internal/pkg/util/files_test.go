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
	"io/fs"
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

// WriteFileIfChanged decides whether a profile or policy file on the node gets
// rewritten, which in turn decides whether it gets reloaded.
func TestWriteFileIfChanged(t *testing.T) {
	t.Parallel()

	t.Run("writes a file that does not exist", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")

		written, err := WriteFileIfChanged(path, []byte("content"), 0o600)
		require.NoError(t, err)
		require.True(t, written)

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "content", string(got))
	})

	t.Run("does not rewrite identical content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

		written, err := WriteFileIfChanged(path, []byte("content"), 0o600)
		require.NoError(t, err)
		require.False(t, written, "an unchanged policy must not trigger a reload")
	})

	t.Run("rewrites changed content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))

		written, err := WriteFileIfChanged(path, []byte("new"), 0o600)
		require.NoError(t, err)
		require.True(t, written)

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "new", string(got))
	})

	t.Run("a longer file differs from content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, []byte("content and more"), 0o600))

		written, err := WriteFileIfChanged(path, []byte("content"), 0o600)
		require.NoError(t, err)
		require.True(t, written)
	})

	t.Run("an empty file differs from content", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "policy.cil")
		require.NoError(t, os.WriteFile(path, nil, 0o600))

		written, err := WriteFileIfChanged(path, []byte("content"), 0o600)
		require.NoError(t, err)
		require.True(t, written)
	})

	t.Run("fails when the path is a directory", func(t *testing.T) {
		t.Parallel()

		// A directory cannot be read or replaced by a policy file.
		dir := t.TempDir()

		_, err := WriteFileIfChanged(dir, []byte("content"), 0o600)
		require.Error(t, err)
	})
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	t.Parallel()

	name := filepath.Join(t.TempDir(), "missing", "profile.json")
	require.Error(t, WriteFileAtomic(name, []byte("data"), 0o600))
}

// The errors name the target instead of the random temporary file, so that
// a status which reports them does not change with every attempt.
func TestWriteFileAtomicStableErrors(t *testing.T) {
	t.Parallel()

	// Renaming the temporary file over a directory fails.
	name := t.TempDir()

	err := WriteFileAtomic(name, []byte("data"), 0o600)
	require.ErrorContains(t, err, "renaming temporary file: rename "+name+": ")
	require.NotContains(t, err.Error(), tempFilePrefix)

	var pathErr *fs.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, name, pathErr.Path)

	// Creating it fails in a missing directory.
	missing := filepath.Join(t.TempDir(), "missing", "profile.json")
	err = WriteFileAtomic(missing, []byte("data"), 0o600)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.ErrorContains(
		t,
		err,
		"open "+filepath.Join(filepath.Dir(missing), tempFilePrefix+"*")+": ",
	)
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
