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

package converter

import (
	"encoding/json"
	"fmt"
	"log"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
)

// Converter is the main structure of this package.
type Converter struct {
	impl
	options *Options
}

// New returns a new Converter instance.
func New(options *Options) *Converter {
	return &Converter{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Converter.
func (p *Converter) Run() error {
	log.Printf("Converting %s to raw profile", p.options.inputFile)

	content, err := p.ReadFile(p.options.inputFile)
	if err != nil {
		return fmt.Errorf("read profile file %s: %w", p.options.inputFile, err)
	}

	profile, err := artifact.ReadProfile(content)
	if err != nil {
		return fmt.Errorf("decoding %s: %w", p.options.inputFile, err)
	}

	var out []byte

	switch obj := profile.(type) {
	case *apparmorprofileapi.AppArmorProfile:
		programName := p.options.programName
		if programName == "" {
			//nolint:lll  // long url is long
			log.Printf("Creating an unattached AppArmor profile '%s'. "+
				"Unattached profiles are not automatically attached to applications, see "+
				"https://web.archive.org/web/20231211031731/https://documentation.suse.com/sles/15-SP3/html/SLES-all/cha-apparmor-profiles.html#sec-apparmor-profiles-types. "+
				"Pass --%s to create a standard profile.",
				obj.Name, FlagProgramName)

			programName = obj.Name
		}

		outStr, err := crd2armor.GenerateProfile(programName, obj.Spec.Mode, &obj.Spec.Abstract)
		if err != nil {
			return fmt.Errorf("build raw apparmor profile: %w", err)
		}

		out = []byte(outStr)
	case *seccompprofileapi.SeccompProfile:
		// Drop the CRD only fields, they are not part of the OCI runtime-spec
		// seccomp profile and would make the output unusable for container
		// runtimes.
		spec := obj.Spec
		spec.SpecBase = profilebasev1.SpecBase{}

		if spec.BaseProfileName != "" {
			log.Printf(
				"Dropping base profile %q, its syscalls are not part of the raw profile.",
				spec.BaseProfileName,
			)

			spec.BaseProfileName = ""
		}

		// The listener fields are valid runtime-spec, but tie the profile to
		// the seccomp agent of this operator and are rejected in KEP-6061
		// artifacts.
		if spec.ListenerPath != "" || spec.ListenerMetadata != "" {
			log.Print("Dropping the listener fields, they are specific to this operator.")

			spec.ListenerPath = ""
			spec.ListenerMetadata = ""
		}

		if usesNotify(&spec) {
			log.Printf(
				"Profile uses %s, so its consumer has to provide a listener path.",
				seccompprofileapi.ActNotify,
			)
		}

		out, err = json.MarshalIndent(spec, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON profile: %w", err)
		}
	default:
		return fmt.Errorf("cannot convert %T to raw profile", obj)
	}

	const filePermissions = 0o600
	if err := p.WriteFile(p.options.outputFile, out, filePermissions); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	log.Printf("Successfully wrote raw profile to %s.", p.options.outputFile)

	return nil
}

// usesNotify reports whether the profile relies on a seccomp notifier, which
// needs a listener path that the converted raw profile no longer carries.
func usesNotify(spec *seccompprofileapi.SeccompProfileSpec) bool {
	if spec.DefaultAction == seccompprofileapi.ActNotify {
		return true
	}

	for i := range spec.Syscalls {
		if spec.Syscalls[i].Action == seccompprofileapi.ActNotify {
			return true
		}
	}

	return false
}
