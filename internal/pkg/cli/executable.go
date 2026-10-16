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
	"os/exec"
	"path/filepath"
)

// ExecutablePath returns the absolute path of the executable of the command,
// which the raw AppArmor profile attaches to. A command name without a path
// is resolved on the PATH like when it gets started, a relative path to the
// working directory. A command which cannot be found, for example the one of
// --no-proc-start, is taken relative to the working directory. AppArmor
// attaches to the executable a symlink resolves to, so they get resolved.
func ExecutablePath(name string) (string, error) {
	if resolved, err := exec.LookPath(name); err == nil {
		name = resolved
	}

	return ResolvePath(name)
}

// ResolvePath returns the absolute path of the file, relative to the working
// directory, with its symlinks resolved if it exists.
func ResolvePath(name string) (string, error) {
	path, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}

	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, nil
	}

	return path, nil
}
