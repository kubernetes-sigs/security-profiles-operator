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

	"sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
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
)

type binary struct {
	name string
}

func newBinary(name string) *binary {
	return &binary{
		name: name,
	}
}

func (b *binary) binaryName() string {
	return b.name
}

func (b *binary) profileFilename() string {
	return "spo_" + strings.Trim(strings.ReplaceAll(b.name, "/", "."), ".")
}

func (b *binary) profileName() string {
	return b.profileFilename()
}

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

func (a *aaProfileManager) RemoveProfile(bp profilebasev1alpha1.StatusBaseUser) error {
	profile, ok := bp.(*v1alpha1.AppArmorProfile)
	if !ok {
		return errors.New(errInvalidCustomResourceType)
	}

	return a.removeProfile(a.logger,
		profile.GetProfileName())
}

func (a *aaProfileManager) InstallProfile(bp profilebasev1alpha1.StatusBaseUser) (bool, error) {
	profile, ok := bp.(*v1alpha1.AppArmorProfile)
	if !ok {
		return false, errors.New(errInvalidCustomResourceType)
	}

	b := newBinary(profile.GetProfileName())
	policy, err := crd2armor.GenerateProfile(
		b.profileName(), b.binaryName(), profile.Spec.ComplainMode, &profile.Spec.Abstract)
	if err != nil {
		return false, fmt.Errorf("generating raw apparmor profile: %w", err)
	}

	return a.loadProfile(a.logger, profile.GetProfileName(), policy)
}

func (a *aaProfileManager) CustomResourceTypeName() string {
	return customResourceTypeName
}

func loadProfile(logger logr.Logger, name, content string) (bool, error) {
	mount := hostop.NewMountHostOp(
		hostop.WithLogger(logger),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(logger))

	err := mount.Do(func() error {
		// AppArmor convention: A profile for /bin/foo is typically named `bin.foo`.
		b := newBinary(name)
		path := filepath.Join(
			targetProfileDir,
			b.profileFilename(),
		)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint // file permissions are fine
			return fmt.Errorf("writing policy file: %w", err)
		}

		if err := a.LoadPolicy(path); err != nil {
			return fmt.Errorf("load policy: %w", err)
		}

		loaded, err := a.PolicyLoaded(b.profileName())
		if err != nil {
			return fmt.Errorf("cannot check policy status: %w", err)
		}

		if !loaded {
			return fmt.Errorf("policy %q is not loaded: AppArmorProfile name must match defined policy",
				b.profileName())
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
		b := newBinary(profileName)
		loaded, err := a.PolicyLoaded(b.profileName())
		if err != nil {
			return fmt.Errorf("cannot check policy status: %w", err)
		}

		if !loaded {
			logger.Info("profile is not loaded into host: skipping deletion", "profile-name", b.profileFilename())

			return nil
		}

		if err := a.DeletePolicy(b.profileName()); err != nil {
			return err
		}

		return os.Remove(filepath.Join(targetProfileDir, b.profileFilename()))
	})

	return err
}
