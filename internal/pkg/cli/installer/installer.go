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

package installer

import (
	"errors"
	"fmt"
	"log"

	"github.com/go-logr/logr"
	"github.com/hairyhenderson/go-which"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
)

// ErrAppArmorUnavailable is returned if AppArmor profiles cannot be loaded
// on the local machine.
var ErrAppArmorUnavailable = errors.New(
	"insufficient permissions or AppArmor is unavailable, " +
		"run spoc as root on a host with AppArmor enabled",
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

	profile, err := AppArmorProfile(content, p.options, "install")
	if err != nil {
		return err
	}

	manager := apparmorprofile.NewAppArmorProfileManager(p.logger)
	if !p.AppArmorEnabled(manager) {
		return ErrAppArmorUnavailable
	}

	p.logger.Info("Installing AppArmor profile", "profile", profile.Name)

	if _, err := p.AppArmorInstallProfile(manager, profile); err != nil {
		return fmt.Errorf("install apparmor profile: %w", err)
	}

	return nil
}

// AppArmorProfile parses the AppArmor profile of the file of the options and
// names it after the executable it confines. action is what the caller does
// with it, for the errors.
func AppArmorProfile(
	content []byte, options *Options, action string,
) (*apparmorprofileapi.AppArmorProfile, error) {
	profile, err := artifact.ReadProfile(content)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", options.ProfilePath, err)
	}

	obj, ok := profile.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return nil, fmt.Errorf(
			"cannot %s %s profiles, only AppArmorProfile is supported",
			action, profile.GetObjectKind().GroupVersionKind().Kind,
		)
	}

	if err := PatchProfileName(obj, options); err != nil {
		return nil, fmt.Errorf("cannot %s apparmor profile: %w", action, err)
	}

	return obj, nil
}

func PatchProfileName(profile *apparmorprofileapi.AppArmorProfile, options *Options) error {
	if options.ExecutablePath != "" {
		profile.Name = options.ExecutablePath
	} else {
		// The profile name may as well be a command on the PATH, whose
		// executable the profile then confines.
		if resolved := which.Which(profile.Name); resolved != "" {
			log.Printf("Resolved profile name %s to executable %s", profile.Name, resolved)
			profile.Name = resolved
		}
	}

	if profile.Name == "" {
		return errors.New("apparmor profile has an empty name")
	}

	return nil
}
