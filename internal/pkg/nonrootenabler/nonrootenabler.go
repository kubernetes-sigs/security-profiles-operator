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

package nonrootenabler

import (
	"os"

	"github.com/pkg/errors"
	"k8s.io/release/pkg/util"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// NonRootEnabler is the main type of this package.
type NonRootEnabler struct {
	impl
}

// New creates a new NonRootEnabler instance.
func New() *NonRootEnabler {
	return &NonRootEnabler{&defaultImpl{}}
}

// SetImpl can be used to set the internal implementation of the
// NonRootEnabler.
func (n *NonRootEnabler) SetImpl(i impl) {
	n.impl = i
}

// Run executes the NonRootEnabler and returns an error if anything fails.
func (n *NonRootEnabler) Run() error {
	const dirPermissions os.FileMode = 0o744

	if err := n.impl.MkdirAll(
		config.KubeletSeccompRootPath, dirPermissions,
	); err != nil {
		return errors.Wrapf(
			err, "create seccomp root path %s", config.KubeletSeccompRootPath,
		)
	}

	if err := n.impl.MkdirAll(
		config.OperatorRoot, dirPermissions,
	); err != nil {
		return errors.Wrapf(
			err, "create operator root path %s", config.KubeletSeccompRootPath,
		)
	}
	// In case the directory already existed
	if err := n.impl.Chmod(config.OperatorRoot, dirPermissions); err != nil {
		return errors.Wrap(err, "change operator root path permissions")
	}

	if _, err := n.impl.Stat(config.ProfilesRootPath); os.IsNotExist(err) {
		if err := n.impl.Symlink(
			config.OperatorRoot, config.ProfilesRootPath,
		); err != nil {
			return errors.Wrap(err, "link profiles root path")
		}
	}

	if err := n.impl.Chown(
		config.OperatorRoot, config.UserRootless, config.UserRootless,
	); err != nil {
		return errors.Wrap(err, "change operator root permissions")
	}

	if err := n.impl.CopyDirContentsLocal(
		"/opt/spo-profiles", config.KubeletSeccompRootPath,
	); err != nil {
		return errors.Wrap(err, "copy local security profiles")
	}

	return nil
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	MkdirAll(path string, perm os.FileMode) error
	Chmod(name string, mode os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	Symlink(oldname, newname string) error
	Chown(name string, uid, gid int) error
	CopyDirContentsLocal(src, dst string) error
}

type defaultImpl struct{}

func (*defaultImpl) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (*defaultImpl) Chmod(name string, perm os.FileMode) error {
	return os.Chmod(name, perm)
}

func (*defaultImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (*defaultImpl) Symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

func (*defaultImpl) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

func (*defaultImpl) CopyDirContentsLocal(src, dst string) error {
	return util.CopyDirContentsLocal(src, dst)
}
