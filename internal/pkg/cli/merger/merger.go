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

package merger

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"slices"

	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
)

// ErrBaseProfileOutdated is returned by Run in check mode when the base
// profile differs from the merge result. Callers are expected to turn this
// into a non-zero exit code without printing it as a failure.
var ErrBaseProfileOutdated = errors.New("base profile needs an update")

// Merger is the main structure of this package.
type Merger struct {
	impl
	options *Options
}

// New returns a new Merger instance.
func New(options *Options) *Merger {
	return &Merger{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Merger.
func (p *Merger) Run() error {
	if p.options.check {
		// The other profiles are checked against the first one.
		log.Printf(
			"Checking %d profiles against %s",
			len(p.options.inputFiles)-1,
			p.options.inputFiles[0],
		)

		if p.options.outputFileSet {
			log.Printf("WARNING: --check writes no output file, ignoring the output file %s",
				p.options.outputFile)
		}
	} else {
		log.Printf("Merging %d profiles into %s", len(p.options.inputFiles), p.options.outputFile)
	}

	contents := make([]client.Object, len(p.options.inputFiles))

	for i, filepath := range p.options.inputFiles {
		log.Printf("Reading file %s", filepath)

		content, err := p.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("open profile: %w", err)
		}

		contents[i], err = artifact.ReadSingleProfile(content)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filepath, err)
		}

		if prf, ok := contents[i].(*apparmorprofileapi.AppArmorProfile); ok &&
			crd2armor.UsesDeprecatedPtraceRules(&prf.Spec.Abstract) {
			log.Printf("WARNING: %s: %s", filepath, crd2armor.DeprecatedPtraceRulesMessage)
		}
	}

	// The merged profile takes these fields from the base profile. Which one
	// is more permissive depends on the values, so they only get warned
	// about, and do not change the result of the check.
	for i := 1; i < len(contents); i++ {
		for _, field := range differingKeptFields(contents[0], contents[i]) {
			log.Printf(
				"WARNING: %s: the %s differs from the one of %s, which the merged profile keeps",
				p.options.inputFiles[i], field, p.options.inputFiles[0],
			)
		}
	}

	baseProfile, ok := contents[0].DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("base profile %T is not a client.Object", contents[0])
	}

	if err := recordingmerger.NormalizeProfile(baseProfile); err != nil {
		return fmt.Errorf("normalize base profile: %w", err)
	}

	merged, err := recordingmerger.MergeProfiles(contents)
	if err != nil {
		return fmt.Errorf("merge profiles: %w", err)
	}

	if err := recordingmerger.NormalizeProfile(merged); err != nil {
		return fmt.Errorf("normalize merged profile: %w", err)
	}

	if p.options.check {
		if reflect.DeepEqual(baseProfile, merged) {
			log.Println("Base profile is up-to-date.")

			return nil
		}

		log.Println("Base profile needs an update.")

		if err := cli.PrintYAML(merged, os.Stderr); err != nil {
			return fmt.Errorf("print YAML: %w", err)
		}

		return ErrBaseProfileOutdated
	}

	var buffer bytes.Buffer
	if err := cli.PrintYAML(merged, &buffer); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	if err := p.WriteFile(p.options.outputFile, buffer.Bytes(), cli.FilePermissions); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}

// differingKeptFields returns the fields which the merged profile takes from
// the base profile instead of merging them, and which differ in the other
// profile. The unset fields count with their defaults.
func differingKeptFields(base, other client.Object) []string {
	var fields []string

	differs := func(field string, b, o any) {
		if !reflect.DeepEqual(b, o) {
			fields = append(fields, field)
		}
	}

	switch b := base.(type) {
	case *seccompprofileapi.SeccompProfile:
		if o, ok := other.(*seccompprofileapi.SeccompProfile); ok {
			differs("state", specState(b.Spec.State), specState(o.Spec.State))
			differs("defaultAction", b.Spec.DefaultAction, o.Spec.DefaultAction)
			differs("baseProfileName", b.Spec.BaseProfileName, o.Spec.BaseProfileName)
			differs("flags", seccompFlags(b), seccompFlags(o))
			differs("listenerPath", b.Spec.ListenerPath, o.Spec.ListenerPath)
			differs("listenerMetadata", b.Spec.ListenerMetadata, o.Spec.ListenerMetadata)
		}
	case *apparmorprofileapi.AppArmorProfile:
		if o, ok := other.(*apparmorprofileapi.AppArmorProfile); ok {
			differs("state", specState(b.Spec.State), specState(o.Spec.State))
			differs("mode", appArmorMode(b), appArmorMode(o))
		}
	case *selinuxprofileapi.SelinuxProfile:
		if o, ok := other.(*selinuxprofileapi.SelinuxProfile); ok {
			differs("state", specState(b.Spec.State), specState(o.Spec.State))
			differs("mode", selinuxMode(b), selinuxMode(o))
			differs("inherit", selinuxInherit(b), selinuxInherit(o))
		}
	}

	return fields
}

// specState returns the state of a profile, which defaults to Enabled.
func specState(state profilebaseapi.SpecState) profilebaseapi.SpecState {
	if state == "" {
		return profilebaseapi.SpecStateEnabled
	}

	return state
}

// seccompFlags returns the flags of the profile as a set, their order does
// not matter.
func seccompFlags(p *seccompprofileapi.SeccompProfile) map[seccompprofileapi.Flag]struct{} {
	flags := make(map[seccompprofileapi.Flag]struct{}, len(p.Spec.Flags))
	for _, flag := range p.Spec.Flags {
		flags[flag] = struct{}{}
	}

	return flags
}

func appArmorMode(p *apparmorprofileapi.AppArmorProfile) apparmorprofileapi.AppArmorMode {
	if p.Spec.Mode == "" {
		return apparmorprofileapi.AppArmorModeEnforce
	}

	return p.Spec.Mode
}

func selinuxMode(p *selinuxprofileapi.SelinuxProfile) selinuxprofileapi.SelinuxMode {
	if p.Spec.Mode == "" {
		return selinuxprofileapi.SelinuxModeEnforcing
	}

	return p.Spec.Mode
}

// selinuxInherit returns the inherited policies of the profile sorted and
// without duplicates, their order has no effect on the policy.
func selinuxInherit(p *selinuxprofileapi.SelinuxProfile) []selinuxprofileapi.PolicyRef {
	if len(p.Spec.Inherit) == 0 {
		return []selinuxprofileapi.PolicyRef{{
			Kind: selinuxprofileapi.SystemPolicyKind, Name: "container",
		}}
	}

	inherit := make([]selinuxprofileapi.PolicyRef, 0, len(p.Spec.Inherit))

	for _, ref := range p.Spec.Inherit {
		if ref.Kind == "" {
			ref.Kind = selinuxprofileapi.SystemPolicyKind
		}

		inherit = append(inherit, ref)
	}

	slices.SortFunc(inherit, func(a, b selinuxprofileapi.PolicyRef) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})

	return slices.Compact(inherit)
}
