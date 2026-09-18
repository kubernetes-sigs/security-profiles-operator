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
)

var (
	hostSupportsAppArmor bool
	checkHostSupport     sync.Once
)

const (
	targetProfileDir string = "/etc/apparmor.d/"

	errInvalidCustomResourceType string = "invalid CRD kind"
	errProfileExists             string = "profile exists"

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

		//nolint:errcheck //(pjbgf): default to false if we are not privileged enough.
		_ = mount.Do(func() (err error) {
			//nolint:errcheck //(pjbgf): default to false if we are not privileged enough.
			hostSupportsAppArmor, _ = appArmor.Enabled()

			return nil
		})
	})

	return hostSupportsAppArmor
}

func (a *aaProfileManager) RemoveProfile(bp profilebaseapi.StatusBaseUser) error {
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
			"profile-name", profile.GetProfileName(), "error", err.Error())

		policy = ""
	}

	return a.removeProfile(a.logger, profile.GetProfileName(), policy)
}

func (a *aaProfileManager) InstallProfile(
	bp profilebaseapi.StatusBaseUser, ownedByUs bool,
) (bool, error) {
	profile, ok := bp.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return false, errors.New(errInvalidCustomResourceType)
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

	return a.loadProfile(a.logger, profile.GetProfileName(), policy)
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
			"profile-name", profileName, "error", err.Error())

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
			"profile-name", profileName, "error", err.Error())

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

func loadProfile(logger logr.Logger, name, content string) (bool, error) {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(logger))

	err := mount.Do(func() error {
		// AppArmor convention: A profile for /bin/foo is typically named `bin.foo`.
		path := filepath.Join(
			targetProfileDir,
			profileFilename(name),
		)
		if err := os.WriteFile(
			path,
			[]byte(managedByMarker+content),
			0o600,
		); err != nil {
			return fmt.Errorf("writing policy file: %w", err)
		}

		if err := a.LoadPolicy(path); err != nil {
			os.Remove(path)

			return fmt.Errorf("load policy: %w", err)
		}

		loaded, err := a.PolicyLoaded(name)
		if err != nil {
			os.Remove(path)

			return fmt.Errorf("cannot check policy status: %w", err)
		}

		if !loaded {
			os.Remove(path)

			return fmt.Errorf(
				"policy %q is not loaded: AppArmorProfile name must match defined policy",
				name,
			)
		}

		return nil
	})

	return err == nil, err
}

func removeProfile(logger logr.Logger, profileName, policy string) error {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(logger))

	err := mount.Do(func() error {
		path := filepath.Join(targetProfileDir, profileFilename(profileName))

		_, statErr := os.Stat(path)
		fileMissing := errors.Is(statErr, os.ErrNotExist)

		// Deleting a custom resource must never unload or delete a profile the
		// host owns. Without this, creating an AppArmorProfile named after a
		// host profile and deleting it again removes the host's profile, even
		// though InstallProfile refused to overwrite it.
		//
		// A missing file is not a host profile to protect: there is nothing at
		// our managed location to own. Treating it as "not ours" would leave a
		// policy this operator loaded, and whose file someone has since removed,
		// in the kernel with no way to unload it.
		if !fileMissing && !fileManagedByUs(path) && !fileHasContent(path, policy) {
			logger.Info(
				"profile is not managed by this operator: skipping deletion",
				"profile-name",
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
				"profile-name",
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
