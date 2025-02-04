/*
Copyright 2025 The Kubernetes Authors.

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

package remover

import (
	"errors"
	"fmt"

	"github.com/go-logr/logr"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/installer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
)

// Remover is the main structure of this package.
type Remover struct {
	impl
	options *installer.Options
	logger  logr.Logger
}

// New returns a new Remover instance.
func New(options *installer.Options, logger logr.Logger) *Remover {
	return &Remover{
		impl:    &defaultImpl{},
		options: options,
		logger:  logger,
	}
}

// Run the Remover.
func (p *Remover) Run() error {
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
			return errors.New("insufficient permissions or AppArmor is unavailable")
		}

		if err := installer.PatchProfileName(obj, p.options); err != nil {
			return fmt.Errorf("cannot remove apparmor profile: %w", err)
		}

		p.logger.Info("Removing AppArmor profile", "profileName", obj.Name)

		if err := p.AppArmorRemoveProfile(manager, obj); err != nil {
			return fmt.Errorf("remove apparmor profile: %w", err)
		}
	default:
		return fmt.Errorf("cannot remove %T profile", obj)
	}

	return nil
}
