/*
Copyright 2020 The Kubernetes Authors.

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

package initialize

import (
	"os"

	"github.com/pkg/errors"
	"k8s.io/release/pkg/util"
)

// SetupRootless creates directory in `operatorRootPath`, sets the group and
// user ID to `guid` and symlinks it to `profilesRootPath`. This is required to
// allow the main container to run as non-root.
func SetupRootless(
	kubeletSeccompRootPath, operatorRootPath, profilesRootPath string,
	guid int,
) error {
	// Create necessary directories
	const perms = 0o744
	if !util.Exists(kubeletSeccompRootPath) {
		if err := os.MkdirAll(kubeletSeccompRootPath, perms); err != nil {
			return errors.Wrapf(
				err, "creating seccomp root path: %s", kubeletSeccompRootPath,
			)
		}
	}

	if err := os.MkdirAll(operatorRootPath, perms); err != nil {
		return errors.Wrapf(
			err, "creating operator root path: %s", operatorRootPath,
		)
	}
	if err := os.Chmod(operatorRootPath, perms); err != nil {
		return errors.Wrapf(
			err, "changing operator root path permissions: %s", operatorRootPath,
		)
	}

	// Symlink if necessary
	if !util.Exists(profilesRootPath) {
		if err := os.Symlink(operatorRootPath, profilesRootPath); err != nil {
			return errors.Wrap(
				err, "linking operator root path into profile root",
			)
		}
	}

	// Change to rootless permissions
	if err := os.Chown(operatorRootPath, guid, guid); err != nil {
		return errors.Wrap(err, "changing operator root path permissions")
	}

	return nil
}
