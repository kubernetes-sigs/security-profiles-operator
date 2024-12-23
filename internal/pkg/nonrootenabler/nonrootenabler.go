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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/go-logr/logr"
	"sigs.k8s.io/release-utils/util"

	"sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
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
func (n *NonRootEnabler) Run(logger logr.Logger, runtime, kubeletDir string, apparmor bool) error {
	const dirPermissions os.FileMode = 0o744
	const filePermissions os.FileMode = 0o644

	logger.Info("Container runtime:" + runtime)

	kubeleteSeccompDir := path.Join(config.HostRoot, kubeletDir, config.SeccompProfilesFolder)
	logger.Info("Ensuring seccomp root path: " + kubeleteSeccompDir)
	if err := n.impl.MkdirAll(
		kubeleteSeccompDir, dirPermissions,
	); err != nil {
		return fmt.Errorf(
			"create seccomp root path %s: %w",
			kubeleteSeccompDir, err,
		)
	}

	logger.Info("Ensuring operator root path: " + config.OperatorRoot)
	if err := n.impl.MkdirAll(
		config.OperatorRoot, dirPermissions,
	); err != nil {
		return fmt.Errorf(
			"create operator root path %s: %w",
			config.OperatorRoot, err,
		)
	}

	logger.Info("Setting operator root permissions")
	if err := n.impl.Chmod(config.OperatorRoot, dirPermissions); err != nil {
		return fmt.Errorf("change operator root path permissions: %w", err)
	}

	kubeletOperatorDir := path.Join(
		config.HostRoot,
		kubeletDir,
		config.SeccompProfilesFolder,
		config.OperatorProfilesFolder,
	)
	if _, err := n.impl.Stat(kubeletOperatorDir); os.IsNotExist(err) {
		logger.Info("Linking profiles root path")
		if err := n.impl.Symlink(
			config.OperatorRoot, kubeletOperatorDir,
		); err != nil {
			return fmt.Errorf("link profiles root path: %w", err)
		}
	}

	logger.Info("Saving kubelet configuration")
	kubeletCfg := config.KubeletConfig{
		KubeletDir: kubeletDir,
	}
	cfg, err := json.Marshal(kubeletCfg)
	if err != nil {
		return fmt.Errorf("marshaling kubelet config: %w", err)
	}
	if err := n.impl.SaveKubeletConfig(
		config.KubeletConfigFilePath(),
		cfg,
		filePermissions,
	); err != nil {
		return fmt.Errorf("saving kubelet config: %w", err)
	}

	logger.Info("Setting operator root user and group")
	if err := n.impl.Chown(
		config.OperatorRoot, config.UserRootless, config.UserRootless,
	); err != nil {
		return fmt.Errorf("change operator root permissions: %w", err)
	}

	logger.Info("Copying profiles into root path: " + kubeleteSeccompDir)
	if err := n.impl.CopyDirContentsLocal(
		config.DefaultSpoProfilePath, kubeleteSeccompDir,
	); err != nil {
		return fmt.Errorf("copy local security profiles: %w", err)
	}

	aaManager := apparmorprofile.NewAppArmorProfileManager(logger)
	if apparmor && aaManager.Enabled() {
		for _, p := range []string{config.SpoApparmorProfile, config.BpfRecorderApparmorProfile} {
			profile := path.Join(config.DefaultSpoProfilePath, p)
			logger.Info("Installing apparmor profile: " + profile)
			if err := n.impl.InsatllApparmor(aaManager, profile); err != nil {
				return fmt.Errorf("installing apparmor profile: %w", err)
			}
		}
	}

	return nil
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	MkdirAll(dirpath string, perm os.FileMode) error
	Chmod(name string, mode os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	Symlink(oldname, newname string) error
	Chown(name string, uid, gid int) error
	CopyDirContentsLocal(src, dst string) error
	SaveKubeletConfig(filename string, kubeletConfig []byte, perm os.FileMode) error
	InsatllApparmor(manager apparmorprofile.ProfileManager, filename string) error
}

type defaultImpl struct{}

func (*defaultImpl) MkdirAll(dirpath string, perm os.FileMode) error {
	return os.MkdirAll(dirpath, perm)
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

func (*defaultImpl) SaveKubeletConfig(filename string, kubeletConfig []byte, perm os.FileMode) error {
	return os.WriteFile(filename, kubeletConfig, perm)
}

func (*defaultImpl) InsatllApparmor(manager apparmorprofile.ProfileManager, filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading apparmor profile content: %w", err)
	}
	profile, err := artifact.ReadProfile(content)
	if err != nil {
		return fmt.Errorf("parsing apparmor profile: %w", err)
	}
	ap, ok := profile.(*v1alpha1.AppArmorProfile)
	if !ok {
		return errors.New("failed converting apparmor profile")
	}
	if _, err := manager.InstallProfile(ap); err != nil {
		return fmt.Errorf("installing apparmor profile: %w", err)
	}
	return nil
}
