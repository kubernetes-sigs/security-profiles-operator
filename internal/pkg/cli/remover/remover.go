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

package remover

import (
	"fmt"

	"github.com/go-logr/logr"

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

	profile, err := installer.AppArmorProfile(content, p.options, "remove")
	if err != nil {
		return err
	}

	manager := apparmorprofile.NewAppArmorProfileManager(p.logger)
	if !p.AppArmorEnabled(manager) {
		return installer.ErrAppArmorUnavailable
	}

	p.logger.Info("Removing AppArmor profile", "profile", profile.Name)

	if err := p.AppArmorRemoveProfile(manager, profile); err != nil {
		return fmt.Errorf("remove apparmor profile: %w", err)
	}

	return nil
}
