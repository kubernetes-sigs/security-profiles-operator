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
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-logr/logr"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
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

	profile, _, err := AppArmorProfile(content, p.options, "install")
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
// names it after the executable it confines. It returns the name before
// resolving the executable as well, which earlier releases named the
// profile with. action is what the caller does with it, for the errors.
func AppArmorProfile(
	content []byte, options *Options, action string,
) (profile *apparmorprofileapi.AppArmorProfile, unresolved string, err error) {
	obj, err := artifact.ReadSingleProfile(content)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read %s: %w", options.ProfilePath, err)
	}

	profile, ok := obj.(*apparmorprofileapi.AppArmorProfile)
	if !ok {
		return nil, "", fmt.Errorf(
			"cannot %s %s profiles, only AppArmorProfile is supported",
			action, obj.GetObjectKind().GroupVersionKind().Kind,
		)
	}

	unresolved, err = executable(profile, options)
	if err != nil {
		return nil, "", fmt.Errorf("cannot %s apparmor profile: %w", action, err)
	}

	return profile, unresolved, nil
}

// executable names the profile after the executable it confines, and returns
// that executable as earlier releases named the profile: the path of the
// options as given, or the command on the PATH the profile is named after. A
// path of the options is a path, never a command on the PATH. AppArmor
// attaches a profile to the absolute path of the executable a symlink
// resolves to, a profile named otherwise does not attach to anything.
func executable(
	profile *apparmorprofileapi.AppArmorProfile, options *Options,
) (unresolved string, err error) {
	unresolved = options.ExecutablePath
	isExecutable := unresolved != ""

	if !isExecutable {
		unresolved = profile.Name

		if found, err := exec.LookPath(profile.Name); err == nil {
			unresolved = found
			isExecutable = true
		}
	}

	if unresolved == "" {
		return "", errors.New("apparmor profile has an empty name")
	}

	// A profile name which is no command keeps its name.
	if isExecutable {
		resolved, err := cli.ResolvePath(unresolved)
		if err != nil {
			return "", fmt.Errorf("resolve executable %s: %w", unresolved, err)
		}

		if _, err := os.Stat(resolved); err != nil {
			log.Printf(
				"Executable %s does not exist, the profile attaches to it once it does",
				resolved,
			)
		}

		if resolved != profile.Name {
			log.Printf("Resolved profile name %s to executable %s", unresolved, resolved)
		}

		profile.Name = resolved
	}

	if !filepath.IsAbs(profile.Name) {
		log.Printf(
			"Profile name %s is no absolute path, the profile does not attach to an executable",
			profile.Name,
		)
	}

	return unresolved, nil
}
