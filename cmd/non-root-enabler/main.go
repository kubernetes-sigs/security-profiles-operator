/*
Copyright 2021 The Kubernetes Authors.

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

package main

import (
	"log"
	"os"

	"github.com/pkg/errors"
	"k8s.io/release/pkg/util"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func main() {
	log.Printf("Enabling non root capabilities for operator")
	if err := run(); err != nil {
		log.Fatalf("Unable to run non root enabler: %v", err)
	}
	log.Printf("Done")
}

func run() error {
	const dirPermissions os.FileMode = 0o744

	if err := os.MkdirAll(
		config.KubeletSeccompRootPath, dirPermissions,
	); err != nil {
		return errors.Wrapf(
			err, "create seccomp root path %s", config.KubeletSeccompRootPath,
		)
	}

	if err := os.MkdirAll(
		config.OperatorRoot, dirPermissions,
	); err != nil {
		return errors.Wrapf(
			err, "create operator root path %s", config.KubeletSeccompRootPath,
		)
	}

	if _, err := os.Stat(config.ProfilesRootPath); os.IsNotExist(err) {
		if err := os.Symlink(
			config.OperatorRoot, config.ProfilesRootPath,
		); err != nil {
			return errors.Wrap(err, "link profiles root path")
		}
	}

	if err := os.Chown(
		config.OperatorRoot, config.UserRootless, config.UserRootless,
	); err != nil {
		return errors.Wrap(err, "change operator root permissions")
	}

	if err := util.CopyDirContentsLocal(
		"/opt/seccomp-profiles", config.KubeletSeccompRootPath,
	); err != nil {
		return errors.Wrap(err, "copy local seccomp profiles")
	}

	return nil
}
