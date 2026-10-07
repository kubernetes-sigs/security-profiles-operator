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

package nonrootenabler

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/moby/sys/mountinfo"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// ErrKubeletDirNotMounted is returned if the kubelet directory of the node is
// not mounted from the host.
var ErrKubeletDirNotMounted = errors.New("kubelet directory not mounted")

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

const (
	dirPermissions  os.FileMode = 0o744
	filePermissions os.FileMode = 0o644
)

// Run executes the NonRootEnabler and returns an error if anything fails.
func (n *NonRootEnabler) Run(logger logr.Logger, runtime, kubeletDir string, apparmor bool) error {
	logger.Info("Container runtime", "runtime", runtime)

	kubeletSeccompDir, err := n.ensureDirs(logger, kubeletDir)
	if err != nil {
		return err
	}

	if err := n.saveKubeletConfig(logger, kubeletDir); err != nil {
		return err
	}

	logger.Info("Setting operator root user and group")

	if err := n.Lchown(
		config.OperatorRoot, config.UserRootless, config.UserRootless,
	); err != nil {
		return fmt.Errorf("change operator root permissions: %w", err)
	}

	logger.Info("Copying profiles into root path", "path", kubeletSeccompDir)

	// Only the seccomp profiles: the directory is a ConfigMap volume, which
	// holds other files and the symlinks of its own layout as well.
	for _, profile := range seccompProfiles {
		if err := n.CopyFile(
			path.Join(config.DefaultSpoProfilePath, profile),
			path.Join(kubeletSeccompDir, profile),
			filePermissions,
		); err != nil {
			return fmt.Errorf("copy local security profile %s: %w", profile, err)
		}
	}

	if !apparmor {
		return nil
	}

	return n.installApparmorProfiles(logger, apparmorprofile.NewAppArmorProfileManager(logger))
}

// ensureDirs creates the seccomp directory of the kubelet and the operator
// root, and links the operator directory of the kubelet to the operator root.
// It returns the seccomp directory of the kubelet.
func (n *NonRootEnabler) ensureDirs(logger logr.Logger, kubeletDir string) (string, error) {
	// Only the seccomp directories of the kubelet directories are mounted
	// from the host below config.HostRoot, not the host root filesystem and
	// not the rest of the kubelet directory, which holds the secret volumes
	// of every pod on the node. Fail if the one of this node is missing
	// rather than writing into the container filesystem. The operator adds
	// the mount once it has seen the node label and the pod gets recreated.
	// The path has to be a mount point itself: it exists as well for a parent
	// of another mount, like /host/var/lib for /host/var/lib/kubelet/seccomp.
	hostKubeletDir := path.Join(config.HostRoot, kubeletDir)
	kubeletSeccompDir := path.Join(hostKubeletDir, config.SeccompProfilesFolder)

	mounted, err := n.Mounted(kubeletSeccompDir)
	if err != nil {
		return "", fmt.Errorf(
			"checking if kubelet seccomp directory %s is mounted at %s: %w",
			kubeletDir, kubeletSeccompDir, err,
		)
	}

	if !mounted {
		return "", fmt.Errorf(
			"%w: kubelet seccomp directory %s at %s",
			ErrKubeletDirNotMounted, kubeletDir, kubeletSeccompDir,
		)
	}

	logger.Info("Ensuring seccomp root path", "path", kubeletSeccompDir)

	if err := n.MkdirAll(
		kubeletSeccompDir, dirPermissions,
	); err != nil {
		return "", fmt.Errorf(
			"create seccomp root path %s: %w",
			kubeletSeccompDir, err,
		)
	}

	logger.Info("Ensuring operator root path", "path", config.OperatorRoot)

	if err := n.MkdirAll(
		config.OperatorRoot, dirPermissions,
	); err != nil {
		return "", fmt.Errorf(
			"create operator root path %s: %w",
			config.OperatorRoot, err,
		)
	}

	logger.Info("Setting operator root permissions")

	if err := n.Chmod(config.OperatorRoot, dirPermissions); err != nil {
		return "", fmt.Errorf("change operator root path permissions: %w", err)
	}

	kubeletOperatorDir := path.Join(kubeletSeccompDir, config.OperatorProfilesFolder)
	if err := n.linkProfilesRoot(logger, kubeletOperatorDir); err != nil {
		return "", err
	}

	return kubeletSeccompDir, nil
}

// saveKubeletConfig saves the kubelet directory for the other components of
// the daemon.
func (n *NonRootEnabler) saveKubeletConfig(logger logr.Logger, kubeletDir string) error {
	logger.Info("Saving kubelet configuration")

	cfg, err := json.Marshal(config.KubeletConfig{KubeletDir: kubeletDir})
	if err != nil {
		return fmt.Errorf("marshaling kubelet config: %w", err)
	}

	if err := n.SaveKubeletConfig(
		config.KubeletConfigFilePath(),
		cfg,
		filePermissions,
	); err != nil {
		return fmt.Errorf("saving kubelet config: %w", err)
	}

	return nil
}

// seccompProfiles are the seccomp profiles of the operator itself, which the
// containers of the daemon run with.
var seccompProfiles = []string{config.SpoSeccompProfile, config.BpfRecorderSeccompProfile}

// apparmorProfiles are the AppArmor profiles of the operator itself, which
// get installed on nodes with AppArmor.
var apparmorProfiles = []string{config.SpoApparmorProfile, config.BpfRecorderApparmorProfile}

// installApparmorProfiles installs the AppArmor profiles of the operator if
// the node supports AppArmor.
func (n *NonRootEnabler) installApparmorProfiles(
	logger logr.Logger, manager apparmorprofile.ProfileManager,
) error {
	if !manager.Enabled() {
		return nil
	}

	for _, p := range apparmorProfiles {
		profile := path.Join(config.DefaultSpoProfilePath, p)
		logger.Info("Installing apparmor profile", "profile", profile)

		if err := n.InstallApparmor(manager, profile); err != nil {
			return fmt.Errorf("installing apparmor profile: %w", err)
		}
	}

	return nil
}

// linkProfilesRoot ensures that the operator directory of the kubelet seccomp
// directory is a symlink to the operator root, where the daemon writes the
// profiles. A link with another target, like one of a previous installation,
// and an empty directory are replaced. Anything else is an error, because the
// kubelet would not find the profiles of the daemon there.
func (n *NonRootEnabler) linkProfilesRoot(logger logr.Logger, kubeletOperatorDir string) error {
	target, err := n.Readlink(kubeletOperatorDir)

	switch {
	case err == nil && target == config.OperatorRoot:
		return nil

	case err == nil:
		logger.Info(
			"Replacing profiles root path link", "path", kubeletOperatorDir, "target", target,
		)

		if err := n.Remove(kubeletOperatorDir); err != nil {
			return fmt.Errorf("remove profiles root path link: %w", err)
		}

	case errors.Is(err, os.ErrNotExist):
		logger.Info("Linking profiles root path")

	// Not a link.
	case errors.Is(err, syscall.EINVAL):
		logger.Info("Replacing profiles root path directory", "path", kubeletOperatorDir)

		if err := n.Rmdir(kubeletOperatorDir); err != nil {
			return fmt.Errorf(
				"%s has to be a link to %s, remove it: %w",
				kubeletOperatorDir, config.OperatorRoot, err,
			)
		}

	default:
		return fmt.Errorf("read profiles root path link %s: %w", kubeletOperatorDir, err)
	}

	if err := n.Symlink(config.OperatorRoot, kubeletOperatorDir); err != nil {
		return fmt.Errorf("link profiles root path: %w", err)
	}

	return nil
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	MkdirAll(dirpath string, perm os.FileMode) error
	Chmod(name string, mode os.FileMode) error
	Readlink(name string) (string, error)
	Remove(name string) error
	Rmdir(name string) error
	Mounted(name string) (bool, error)
	Symlink(oldname, newname string) error
	Lchown(name string, uid, gid int) error
	CopyFile(src, dst string, perm os.FileMode) error
	SaveKubeletConfig(filename string, kubeletConfig []byte, perm os.FileMode) error
	InstallApparmor(manager apparmorprofile.ProfileManager, filename string) error
}

type defaultImpl struct{}

func (*defaultImpl) MkdirAll(dirpath string, perm os.FileMode) error {
	return os.MkdirAll(dirpath, perm)
}

func (*defaultImpl) Chmod(name string, perm os.FileMode) error {
	return os.Chmod(name, perm)
}

func (*defaultImpl) Readlink(name string) (string, error) {
	return os.Readlink(name)
}

func (*defaultImpl) Remove(name string) error {
	return os.Remove(name)
}

// Rmdir removes the empty directory name, and fails for anything else.
func (*defaultImpl) Rmdir(name string) error {
	if err := syscall.Rmdir(name); err != nil {
		return &os.PathError{Op: "rmdir", Path: name, Err: err}
	}

	return nil
}

func (*defaultImpl) Mounted(name string) (bool, error) {
	return mountinfo.Mounted(name)
}

func (*defaultImpl) Symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

func (*defaultImpl) Lchown(name string, uid, gid int) error {
	return os.Lchown(name, uid, gid)
}

// CopyFile copies the file src to dst, which a reader never sees partially
// written.
func (*defaultImpl) CopyFile(src, dst string, perm os.FileMode) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}

	if err := util.WriteFileAtomic(dst, content, perm); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}

	return nil
}

func (*defaultImpl) SaveKubeletConfig(
	filename string,
	kubeletConfig []byte,
	perm os.FileMode,
) error {
	// The daemon reads the file while it may get written.
	return util.WriteFileAtomic(filename, kubeletConfig, perm)
}

func (*defaultImpl) InstallApparmor(manager apparmorprofile.ProfileManager, filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("reading apparmor profile content: %w", err)
	}

	profile, err := artifact.ReadProfile(content)
	if err != nil {
		return fmt.Errorf("parsing apparmor profile: %w", err)
	}

	ap, ok := profile.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return errors.New("failed converting apparmor profile")
	}

	// These are the operator's own bundled profiles, shipped in the image, so
	// they are ours by construction. Passing false here would make the init
	// container fail on every upgrade from a release that installed them before
	// the ownership marker existed: the policy is loaded and its file carries no
	// marker, so the guard would refuse to replace it and crash-loop the pod.
	if _, err := manager.InstallProfile(ap, true); err != nil {
		return fmt.Errorf("installing apparmor profile: %w", err)
	}

	return nil
}
