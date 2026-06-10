//go:build apparmor

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

package apparmorprofile

import (
	"errors"
	"fmt"
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
	customResourceTypeName string = "AppArmorProfile"
	targetProfileDir       string = "/etc/apparmor.d/"

	errInvalidCustomResourceType string = "invalid CRD kind"
	errProfileExists             string = "profile exists"
)

func (a *aaProfileManager) Enabled() bool {
	checkHostSupport.Do(func() {
		mount := hostop.NewMountHostOp(
			hostop.WithLogger(a.logger),
			hostop.WithAssumeContainer(),
			hostop.WithAssumeHostPidNamespace())
		a := aa.NewAppArmor(aa.WithLogger(a.logger))

		//nolint:errcheck //(pjbgf): default to false if we are not privileged enough.
		_ = mount.Do(func() (err error) {
			//nolint:errcheck //(pjbgf): default to false if we are not privileged enough.
			hostSupportsAppArmor, _ = a.Enabled()

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

	return a.removeProfile(a.logger, profile.GetProfileName())
}

func (a *aaProfileManager) InstallProfile(bp profilebaseapi.StatusBaseUser) (bool, error) {
	profile, ok := bp.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return false, errors.New(errInvalidCustomResourceType)
	}

	// Avoid overwriting an existing profile first time when a new profile is installed.
	// We check if already a profile with the same name already exists, and if so we bail
	// out. This is to prevent an attack vector when someone wants to overwrite a well-known
	// profile existing into a cluster node.
	if profile.Generation == 1 && a.checkProfileExist(a.logger, profile.GetProfileName()) {
		return false, errors.New(errProfileExists)
	}

	policy, err := crd2armor.GenerateProfile(profile.GetProfileName(), profile.Spec.Mode, &profile.Spec.Abstract)
	if err != nil {
		return false, fmt.Errorf("generating raw apparmor profile: %w", err)
	}

	return a.loadProfile(a.logger, profile.GetProfileName(), policy)
}

func (a *aaProfileManager) CustomResourceTypeName() string {
	return customResourceTypeName
}

func profileFilename(profileName string) string {
	return strings.Trim(strings.ReplaceAll(profileName, "/", "."), ".")
}

// checkProfileExists checks if an profile is already loaded into the kernel.
func checkProfileExist(logger logr.Logger, profileName string) bool {
	apparmor := aa.NewAppArmor(aa.WithLogger(logger))

	loaded, err := apparmor.PolicyLoaded(profileName)
	if err != nil {
		logger.Info("cannot check policy status: assumes profile doesn't exist",
			"profile-name", profileName)

		return false
	}

	if loaded {
		return true
	}

	return false
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
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint // file permissions are fine
			return fmt.Errorf("writing policy file: %w", err)
		}

		if err := a.LoadPolicy(path); err != nil {
			return fmt.Errorf("load policy: %w", err)
		}

		loaded, err := a.PolicyLoaded(name)
		if err != nil {
			return fmt.Errorf("cannot check policy status: %w", err)
		}

		if !loaded {
			return fmt.Errorf("policy %q is not loaded: AppArmorProfile name must match defined policy", name)
		}

		return nil
	})

	return err != nil, err
}

func removeProfile(logger logr.Logger, profileName string) error {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(logger))

	err := mount.Do(func() error {
		loaded, err := a.PolicyLoaded(profileName)
		if err != nil {
			return fmt.Errorf("cannot check policy status: %w", err)
		}

		if !loaded {
			logger.Info("profile is not loaded into host: skipping deletion", "profile-name", profileName)

			return nil
		}

		if err := a.DeletePolicy(profileName); err != nil {
			return err
		}

		return os.Remove(filepath.Join(targetProfileDir, profileFilename(profileName)))
	})

	return err
}
