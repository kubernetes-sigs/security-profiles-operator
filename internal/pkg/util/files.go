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
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// tempFilePrefix is the name prefix of the temporary files of WriteFileAtomic.
const tempFilePrefix = ".tmp-"

// tempFileRegexp matches the names createTemp generates: the prefix followed
// by the output of rand.Text, which is 26 characters of base32.
var tempFileRegexp = regexp.MustCompile(`^\.tmp-[A-Z2-7]{26}$`)

// WriteFileIfChanged writes data to name with WriteFileAtomic, unless the file
// holds data already. It reports whether it wrote the file. Rewriting a file
// with the same content would make its watchers reload it for nothing.
func WriteFileIfChanged(name string, data []byte, perm os.FileMode) (bool, error) {
	if fileHolds(name, data) {
		return false, nil
	}

	if err := WriteFileAtomic(name, data, perm); err != nil {
		return false, err
	}

	return true, nil
}

// fileHolds reports whether the file name holds exactly data. A file which
// does not exist or cannot be read holds nothing, the write tells why it
// fails.
func fileHolds(name string, data []byte) bool {
	f, err := os.Open(name)
	if err != nil {
		return false
	}

	defer f.Close()

	// One byte more than data tells a longer file apart.
	existing, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))

	return err == nil && bytes.Equal(existing, data)
}

// WriteFileAtomic writes data to a temporary file next to name, syncs it and
// renames it over name. Readers therefore see either the previous or the new
// content, never a partially written file. The temporary file is hidden and
// does not carry the extension of name, so directory watchers matching on the
// extension ignore it. Its name does not embed the base name of name either,
// so it cannot exceed the file name length limit when name does not.
//
// The file is created with perm, subject to the umask like os.WriteFile, and
// never changed afterwards. The seccomp profile of the daemon, which calls
// this, allows neither fchmod nor fchown.
func WriteFileAtomic(name string, data []byte, perm os.FileMode) (retErr error) {
	dir := filepath.Dir(name)

	tmp, err := createTemp(dir, perm)
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}

	defer func() {
		if retErr != nil {
			// Best effort cleanup, the file may already be closed.
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temporary file: %w", withTargetName(err, name))
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary file: %w", withTargetName(err, name))
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", withTargetName(err, name))
	}

	if err := os.Rename(tmp.Name(), name); err != nil {
		return fmt.Errorf("renaming temporary file: %w", withTargetName(err, name))
	}

	return syncDir(dir)
}

// createTemp creates a new hidden file in dir with perm. Unlike os.CreateTemp,
// which always uses 0o600, it takes the permissions, so that they do not have
// to be changed afterwards.
func createTemp(dir string, perm os.FileMode) (*os.File, error) {
	const attempts = 100

	for range attempts {
		name := filepath.Join(dir, tempFilePrefix+rand.Text())

		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, os.ErrExist) {
			continue
		}

		if pathErr, ok := errors.AsType[*fs.PathError](err); ok {
			// The random part of the name would make every error differ.
			return nil, &fs.PathError{
				Op: pathErr.Op, Path: filepath.Join(dir, tempFilePrefix+"*"), Err: pathErr.Err,
			}
		}

		return f, err
	}

	return nil, fmt.Errorf("no unused temporary file name in %s after %d attempts", dir, attempts)
}

// withTargetName replaces the name of the temporary file in a path or link
// error by the name of the file it gets renamed to. The random part of its
// name would make every error differ, like the ones reported in a status.
func withTargetName(err error, name string) error {
	if pathErr, ok := errors.AsType[*fs.PathError](err); ok {
		return &fs.PathError{Op: pathErr.Op, Path: name, Err: pathErr.Err}
	}

	if linkErr, ok := errors.AsType[*os.LinkError](err); ok {
		return &fs.PathError{Op: linkErr.Op, Path: name, Err: linkErr.Err}
	}

	return err
}

// syncDir persists the directory entries of dir, like a completed rename.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening directory: %w", err)
	}
	defer d.Close()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("syncing directory: %w", err)
	}

	return nil
}

// RemoveStaleTempFiles removes the temporary files WriteFileAtomic leaves
// behind in dir if the process dies between creating and renaming them. Only
// regular files whose name matches the generated pattern and which were not
// modified for minAge are removed, so that a concurrent writer, for example a
// second daemon during a rolling update, keeps its file. It returns the paths
// of the removed files. A missing dir is not an error.
func RemoveStaleTempFiles(dir string, minAge time.Duration) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	var (
		removed []string
		errs    []error
	)

	for _, entry := range entries {
		if !entry.Type().IsRegular() || !tempFileRegexp.MatchString(entry.Name()) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			// The file may be gone already, renamed by its writer.
			continue
		}

		if time.Since(info.ModTime()) < minAge {
			continue
		}

		name := filepath.Join(dir, entry.Name())
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("removing %s: %w", name, err))

			continue
		}

		removed = append(removed, name)
	}

	return removed, errors.Join(errs...)
}
