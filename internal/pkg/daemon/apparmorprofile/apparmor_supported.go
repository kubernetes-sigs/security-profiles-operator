//go:build apparmor

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

package apparmorprofile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	aa "github.com/pjbgf/go-apparmor/pkg/apparmor"
	"github.com/pjbgf/go-apparmor/pkg/hostop"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

var (
	hostSupportsAppArmor bool
	checkHostSupport     sync.Once
)

const (
	targetProfileDir string = "/etc/apparmor.d/"

	errInvalidCustomResourceType string = "invalid CRD kind"
	errProfileExists             string = "profile exists"
	errRuntimeProfile            string = "profile name is reserved for a container runtime"

	// managedByMarker is written as the first line of every policy file this
	// operator installs, and is what makes a profile ours. Mere existence of a
	// file under targetProfileDir cannot establish ownership: that directory is
	// also where distributions and admins keep their own profiles, so an
	// AppArmorProfile named after one of them ("crun", "busybox", ...) would
	// otherwise be treated as ours and silently overwrite the host's profile.
	managedByMarker string = "# Managed by security-profiles-operator. Do not edit.\n"
)

func (a *aaProfileManager) Enabled() bool {
	checkHostSupport.Do(func() {
		mount := hostop.NewMountHostOp(
			hostop.WithLogger(a.logger),
			hostop.WithAssumeContainer(),
			hostop.WithAssumeHostPidNamespace())
		appArmor := aa.NewAppArmor(aa.WithLogger(a.logger))

		// Both failures leave AppArmor disabled, but they are told apart in
		// the logs: a daemon which lacks the capabilities to enter the host
		// mount namespace, or to read the securityfs, would otherwise report
		// every host as one without AppArmor.
		if err := mount.Do(func() error {
			enabled, err := appArmor.Enabled()
			if err != nil {
				a.logger.Info("AppArmor is not available on the host", "error", err.Error())

				return nil
			}

			hostSupportsAppArmor = enabled

			return nil
		}); err != nil {
			a.logger.Error(
				err,
				"Cannot enter the host mount namespace to detect AppArmor support: assuming the host has none",
			)
		}
	})

	return hostSupportsAppArmor
}

func (a *aaProfileManager) RemoveProfile(bp profilebaseapi.StatusBaseUser, ownedByUs bool) error {
	profile, ok := bp.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return errors.New(errInvalidCustomResourceType)
	}

	// A profile installed before the ownership marker existed carries none, so
	// removal would otherwise skip it and leave the policy loaded for good. The
	// policy this custom resource generates is the second piece of evidence: a
	// file whose content is exactly what we would write is ours, and a host
	// profile of the same name is not going to match it.
	policy, err := crd2armor.GenerateProfile(
		profile.GetProfileName(),
		profile.Spec.Mode,
		&profile.Spec.Abstract,
	)
	if err != nil {
		// Without the generated policy only the marker can establish ownership,
		// which is still correct, just less forgiving on upgrade.
		a.logger.Info("cannot generate policy for ownership check",
			"profile", profile.GetProfileName(), "error", err.Error())

		policy = ""
	}

	return a.removeProfile(a.logger, profile.GetProfileName(), policy, ownedByUs)
}

func (a *aaProfileManager) InstallProfile(
	bp profilebaseapi.StatusBaseUser, ownedByUs bool,
) (bool, error) {
	profile, ok := bp.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return false, errors.New(errInvalidCustomResourceType)
	}

	// A runtime's default profile may not be loaded yet, so the ownership check
	// below would let an AppArmorProfile claim its name and later replace or
	// unload it. Nothing legitimate needs to install one of those names.
	if isRuntimeProfile(profile.GetProfileName()) {
		return false, errors.New(errRuntimeProfile)
	}

	// Avoid overwriting a profile that the host already owns. A policy that is
	// loaded into the kernel but whose file at our managed location does not
	// carry our marker was put there by someone else, so we bail out. This must
	// not be gated on the generation: an attacker would otherwise only need to
	// patch the spec once to get past the check and replace a well-known host
	// profile.
	//
	// ownedByUs is the upgrade path. Profiles installed before the marker
	// existed have none, and the caller is what proves they are ours: this
	// node's own status for a custom resource, or simply being one of the
	// operator's bundled profiles. Reinstalling them here writes the marker, so
	// the migration happens on the first reconcile after the upgrade.
	if a.checkProfileExist(a.logger, profile.GetProfileName()) &&
		!ownedByUs &&
		!a.profileManagedByUs(a.logger, profile.GetProfileName()) {
		return false, errors.New(errProfileExists)
	}

	policy, err := crd2armor.GenerateProfile(
		profile.GetProfileName(),
		profile.Spec.Mode,
		&profile.Spec.Abstract,
	)
	if err != nil {
		return false, fmt.Errorf("generating raw apparmor profile: %w", err)
	}

	return a.loadProfile(a.logger, profile.GetProfileName(), policy, ownedByUs)
}

// runtimeProfiles are the default profiles container runtimes load into the
// kernel themselves, usually without a policy file under targetProfileDir.
// Workloads depend on them, so an AppArmorProfile must never replace them.
var runtimeProfiles = map[string]struct{}{
	"cri-containerd.apparmor.d": {},
	"crio-default":              {},
	"docker-default":            {},
}

// runtimeProfilePrefixes cover the runtime default profiles whose name carries
// the version of the runtime that loaded them.
var runtimeProfilePrefixes = []string{
	"containers-default-",
	"crio-default-",
}

// isRuntimeProfile reports whether name is a container runtime's default
// profile.
func isRuntimeProfile(name string) bool {
	if _, ok := runtimeProfiles[name]; ok {
		return true
	}

	for _, prefix := range runtimeProfilePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	return false
}

func profileFilename(profileName string) string {
	return strings.Trim(strings.ReplaceAll(profileName, "/", "."), ".")
}

// checkProfileExist checks if a profile is already loaded into the kernel. The
// policy list lives in the host's securityfs, so this has to run inside the host
// mount namespace. It fails closed: if the status cannot be determined, the
// profile is reported as existing so that InstallProfile refuses to overwrite
// whatever is loaded.
func checkProfileExist(logger logr.Logger, profileName string) bool {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	apparmor := aa.NewAppArmor(aa.WithLogger(logger))

	exists := true

	if err := mount.Do(func() error {
		loaded, err := apparmor.PolicyLoaded(profileName)
		if err != nil {
			return fmt.Errorf("checking policy status: %w", err)
		}

		exists = loaded

		return nil
	}); err != nil {
		logger.Info("cannot check policy status: assuming the profile exists",
			"profile", profileName, "error", err.Error())

		return true
	}

	return exists
}

// profileManagedByUs reports whether the policy file at the location this
// operator installs to carries our ownership marker, which means a previous
// InstallProfile wrote it. It fails closed: if the host mount namespace cannot
// be entered, the profile is treated as not ours so that checkProfileExist keeps
// protecting it.
func profileManagedByUs(logger logr.Logger, profileName string) bool {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())

	managed := false

	if err := mount.Do(func() error {
		managed = fileManagedByUs(filepath.Join(targetProfileDir, profileFilename(profileName)))

		return nil
	}); err != nil {
		logger.Info("cannot check profile ownership: assuming the profile is not ours",
			"profile", profileName, "error", err.Error())

		return false
	}

	return managed
}

// fileHasContent reports whether the file at path holds exactly want, which
// identifies a profile this operator wrote before the ownership marker existed.
// An empty want never matches. It must be called inside the host mount namespace.
func fileHasContent(path, want string) bool {
	if want == "" {
		return false
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	return string(content) == want
}

// fileManagedByUs reports whether the file at path starts with our ownership
// marker. It must be called inside the host mount namespace.
func fileManagedByUs(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	marker := make([]byte, len(managedByMarker))
	if _, err := io.ReadFull(file, marker); err != nil {
		return false
	}

	return string(marker) == managedByMarker
}

// loadProfile writes the policy into the host and loads it. ownedByUs is the
// caller's evidence that this operator installed the profile, see
// ProfileManager.InstallProfile.
func loadProfile(logger logr.Logger, name, content string, ownedByUs bool) (bool, error) {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(logger))

	var updated bool

	err := mount.Do(func() (err error) {
		// AppArmor convention: A profile for /bin/foo is typically named `bin.foo`.
		path := filepath.Join(
			targetProfileDir,
			profileFilename(name),
		)

		updated, err = loadPolicyFile(logger, a, path, name, content, ownedByUs)

		return err
	})

	return updated, err
}

// policyLoader loads AppArmor policies into the kernel.
type policyLoader interface {
	LoadPolicy(fileName string) error
	PolicyLoaded(policyName string) (bool, error)
}

// errHostPolicyFile is returned if the policy file at the managed location
// belongs to the host.
var errHostPolicyFile = errors.New("policy file belongs to the host")

// loadPolicyFile writes the policy with the given content to path and loads
// it. It returns false without touching anything if the file holds the
// policy already and it is loaded, so that a restart of the daemon or a
// resync neither rewrites every policy file nor runs apparmor_parser for
// each of them. It must be called inside the host mount namespace.
//
// A file at path which is not ours is left alone, even if its policy is not
// loaded: the ownership check of InstallProfile only sees loaded policies, so a
// distribution or admin profile whose service is stopped, which is disabled
// via /etc/apparmor.d/disable or whose binary is absent would otherwise be
// replaced, and the marker written into it would let a later removal delete
// the host's file.
func loadPolicyFile(
	logger logr.Logger, a policyLoader, path, name, content string, ownedByUs bool,
) (bool, error) {
	policy := []byte(managedByMarker + content)

	previous, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return false, fmt.Errorf("reading existing policy file: %w", readErr)
	}

	// A file without the marker which holds exactly the policy we generate
	// was written before the marker existed, so it is ours as well.
	if readErr == nil && !ownedByUs &&
		!bytes.HasPrefix(previous, []byte(managedByMarker)) &&
		string(previous) != content {
		return false, fmt.Errorf("%w: %s", errHostPolicyFile, path)
	}

	if readErr == nil && bytes.Equal(previous, policy) {
		loaded, err := a.PolicyLoaded(name)
		if err != nil {
			return false, fmt.Errorf("cannot check policy status: %w", err)
		}

		if loaded {
			return false, nil
		}
	}

	if err := util.WriteFileAtomic(path, policy, 0o600); err != nil {
		return false, fmt.Errorf("writing policy file: %w", err)
	}

	// The kernel keeps the previously loaded policy when loading an
	// update fails, so put its file back instead of removing it.
	restore := func() {
		if readErr != nil {
			os.Remove(path)

			return
		}

		if err := util.WriteFileAtomic(path, previous, 0o600); err != nil {
			logger.Error(err, "Cannot restore previous policy file", "path", path)
		}
	}

	if err := a.LoadPolicy(path); err != nil {
		restore()

		return false, fmt.Errorf("load policy: %w", err)
	}

	loaded, err := a.PolicyLoaded(name)
	if err != nil {
		restore()

		return false, fmt.Errorf("cannot check policy status: %w", err)
	}

	if !loaded {
		restore()

		return false, fmt.Errorf(
			"policy %q is not loaded: AppArmorProfile name must match defined policy",
			name,
		)
	}

	return true, nil
}

// removeStaleTempFiles removes the temporary files of interrupted policy file
// writes from the host.
func removeStaleTempFiles(logger logr.Logger) {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())

	if err := mount.Do(func() error {
		common.RemoveStaleTempFiles(logger, targetProfileDir)

		return nil
	}); err != nil {
		logger.Error(err, "Cannot remove stale temporary files", "dir", targetProfileDir)
	}
}

// policyFileOwned reports whether removing the profile whose policy file lives
// at path may unload it. A file carrying our marker, or holding exactly the
// policy we would generate, is ours. A missing file proves nothing either way:
// container runtimes load their default profiles (docker-default,
// cri-containerd.apparmor.d, ...) without writing one here, so only ownedByUs,
// the caller's evidence that this operator installed the profile on this node,
// makes it ours. It must be called inside the host mount namespace.
func policyFileOwned(path, policy string, ownedByUs bool) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return ownedByUs
	}

	return fileManagedByUs(path) || fileHasContent(path, policy)
}

func removeProfile(logger logr.Logger, profileName, policy string, ownedByUs bool) error {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(logger))

	err := mount.Do(func() error {
		path := filepath.Join(targetProfileDir, profileFilename(profileName))

		// Deleting a custom resource must never unload or delete a profile the
		// host owns. Without this, creating an AppArmorProfile named after a
		// host profile and deleting it again removes the host's profile, even
		// though InstallProfile refused to overwrite it.
		if !policyFileOwned(path, policy, ownedByUs) {
			logger.Info(
				"profile is not managed by this operator: skipping deletion",
				"profile",
				profileName,
			)

			return nil
		}

		loaded, err := a.PolicyLoaded(profileName)
		if err != nil {
			return fmt.Errorf("cannot check policy status: %w", err)
		}

		if loaded {
			if err := a.DeletePolicy(profileName); err != nil {
				return fmt.Errorf("deleting apparmor policy %s: %w", profileName, err)
			}
		} else {
			logger.Info(
				"profile is not loaded into host: removing the policy file only",
				"profile",
				profileName,
			)
		}

		// Remove the file even when the policy was not loaded, otherwise it
		// stays behind as a stale ownership marker.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("removing policy file %s: %w", path, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("removing apparmor profile: %w", err)
	}

	return nil
}
