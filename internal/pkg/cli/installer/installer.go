/*
Copyright 2024 The Kubernetes Authors.

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

package installer

import (
	"fmt"
	"github.com/go-logr/logr"
	"github.com/hairyhenderson/go-which"
	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
)

// Installer is the main structure of this package.
type Installer struct {
	impl
	options *Options
	logger  logr.Logger
}

// New returns a new Installer instance.
func New(options *Options, logger logr.Logger) *Installer {
	return &Installer{
		impl:    &defaultImpl{},
		options: options,
		logger:  logger,
	}
}

// Run the Installer.
func (p *Installer) Run() error {

	p.logger.Info("Reading profile file", "filename", p.options.ProfilePath)
	content, err := p.ReadFile(p.options.ProfilePath)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}

	profile, err := artifact.ReadProfile(content)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", p.options.ProfilePath, err)
	}

	switch obj := profile.(type) {
	case *apparmorprofileapi.AppArmorProfile:
		manager := apparmorprofile.NewAppArmorProfileManager(p.logger)
		if !p.AppArmorEnabled(manager) {
			return fmt.Errorf("insufficient permissions or AppArmor is unavailable")
		}

		if err := PatchProfileName(obj, p.options); err != nil {
			return fmt.Errorf("cannot create apparmor profile: %w", err)
		}

		p.logger.Info("Installing AppArmor profile", "profileName", obj.Name)
		if _, err := p.AppArmorInstallProfile(manager, obj); err != nil {
			return fmt.Errorf("install apparmor profile: %w", err)
		}
	default:
		return fmt.Errorf("cannot install %T profile", obj)
	}

	return nil
}

func PatchProfileName(profile *apparmorprofileapi.AppArmorProfile, options *Options) error {
	if options.ExecutablePath != "" {
		profile.Name = options.ExecutablePath
	} else {
		if resolved := which.Which(profile.Name); resolved != "" {
			profile.Name = resolved
		}
	}
	if profile.Name == "" {
		return fmt.Errorf("apparmor profile has an empty name")
	}
	return nil
}
