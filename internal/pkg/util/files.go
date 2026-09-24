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
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
		return fmt.Errorf("writing temporary file: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temporary file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}

	if err := os.Rename(tmp.Name(), name); err != nil {
		return fmt.Errorf("renaming temporary file: %w", err)
	}

	return syncDir(dir)
}

// createTemp creates a new hidden file in dir with perm. Unlike os.CreateTemp,
// which always uses 0o600, it takes the permissions, so that they do not have
// to be changed afterwards.
func createTemp(dir string, perm os.FileMode) (*os.File, error) {
	const attempts = 100

	for range attempts {
		name := filepath.Join(dir, ".tmp-"+rand.Text())

		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, os.ErrExist) {
			continue
		}

		return f, err
	}

	return nil, fmt.Errorf("no unused temporary file name in %s after %d attempts", dir, attempts)
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
