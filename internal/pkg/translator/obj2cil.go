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

package translator

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

const (
	typePermissive         = "(typepermissive process)"
	systemContainerInherit = "container"
)

var (
	// blockNameRegexp matches the names CIL accepts for a block declaration:
	// the first character has to be a letter and dots are namespace
	// separators, so they are not allowed. The SelinuxProfile CRD restricts
	// the names further to lowercase letters, digits and '-', while spoc
	// converts profiles from files, whose names only have to be valid CIL.
	blockNameRegexp = regexp.MustCompile(`^[a-zA-Z][-a-zA-Z0-9_]*$`)

	// identifierRegexp matches the SELinux types, object classes, permissions
	// and inherited block names which may be written into a policy. It
	// excludes whitespace and parentheses, which would otherwise allow to
	// inject additional CIL statements, and matches the CRD validation.
	identifierRegexp = regexp.MustCompile(`^[-a-zA-Z0-9._]+$`)

	// permissionKeywords are parsed by CIL as an expression when they appear
	// in a permission list, for example "all" expands to every permission of
	// the class. The denied permissions are compared by name, so these
	// keywords only ever served to bypass them.
	permissionKeywords = map[string]struct{}{
		"all": {}, "and": {}, "not": {}, "or": {}, "range": {}, "xor": {},
	}

	errInvalidIdentifier = errors.New("invalid identifier")
)

// Safe Defaults: Hardcoded denylists to prevent critical privilege escalation.
var (
	// deniedTypes prevents access to critical hosts assets. The types are
	// compared by name, so a type attribute which contains a denied type,
	// like file_type, is not denied.
	deniedTypes = map[string]struct{}{
		"kernel_t":   {}, // Core kernel structures
		"kmem_t":     {}, // Kernel memory
		"security_t": {}, // SELinux fs
		"shadow_t":   {}, // /etc/shadow
	}

	// deniedClasses prevents manipulation of the SELinux system itself. The
	// capabilities within user namespaces, cap_userns and cap2_userns, are
	// not denied by default: denying them breaks the existing profiles which
	// use them. The DeniedClasses of the SPOD can deny them.
	deniedClasses = map[string]struct{}{
		"capability":  {}, // Linux capabilities
		"capability2": {}, // Newer Linux capabilities
		"security":    {}, // Allows managing SELinux state
		"system":      {}, // Core system operations
	}

	// deniedPermissions prevents hostile actions on otherwise standard classes.
	deniedPermissions = map[string]struct{}{
		"load_policy": {}, // Can rewrite SELinux rules
		"mac_admin":   {},
		"mounton":     {},
		"relabelto":   {}, // Can hijack other containers' files
		"relabelfrom": {}, // Can hijack other containers' files
		"setbool":     {},
		"setenforce":  {}, // Can disable SELinux
		"setsecparam": {},
	}
)

// Options defines the options for the Object2CIL translation.
type Options struct {
	// DeniedTypes if specified, a list of SELinux types which are
	// denied in SELinux profiles.
	DeniedTypes []string

	// DeniedClasses if specified, a list of SELinux object classes which are
	// denied in SELinux profiles.
	DeniedClasses []string

	// DeniedPermissions if specified, a list of SELinux permissions which are
	// denied in SELinux profiles.
	DeniedPermissions []string

	// AllowedTypes if specified, a list of SELinux types which are removed
	// from the built-in denylist.
	AllowedTypes []string

	// AllowedClasses if specified, a list of SELinux object classes which are
	// removed from the built-in denylist.
	AllowedClasses []string

	// AllowedPermissions if specified, a list of SELinux permissions which are
	// removed from the built-in denylist.
	AllowedPermissions []string
}

type deniedOptions struct {
	deniedTypes       map[string]struct{}
	deniedClasses     map[string]struct{}
	deniedPermissions map[string]struct{}
}

func deniedOptionsFromOpts(opts *Options) *deniedOptions {
	// Clone the global maps to avoid data races when executed in parallel.
	denied := &deniedOptions{
		deniedTypes:       maps.Clone(deniedTypes),
		deniedClasses:     maps.Clone(deniedClasses),
		deniedPermissions: maps.Clone(deniedPermissions),
	}

	if opts == nil {
		return denied
	}

	// Remove allowed types, classes, and permissions from the default
	// denylist. The names are compared without their empty dot separated
	// components, see globalName.
	for _, t := range opts.AllowedTypes {
		delete(denied.deniedTypes, globalName(t))
	}

	for _, c := range opts.AllowedClasses {
		delete(denied.deniedClasses, globalName(c))
	}

	for _, p := range opts.AllowedPermissions {
		delete(denied.deniedPermissions, globalName(p))
	}

	// Add user-specified denied types, classes, and permissions to the denylist.
	for _, t := range opts.DeniedTypes {
		denied.deniedTypes[globalName(t)] = struct{}{}
	}

	for _, c := range opts.DeniedClasses {
		denied.deniedClasses[globalName(c)] = struct{}{}
	}

	for _, p := range opts.DeniedPermissions {
		denied.deniedPermissions[globalName(p)] = struct{}{}
	}

	return denied
}

func Object2CIL(
	systemInherits []string,
	objInherits []selinuxprofileapi.SelinuxProfileObject,
	sp *selinuxprofileapi.SelinuxProfile,
	options *Options,
) (string, error) {
	if !blockNameRegexp.MatchString(sp.GetName()) {
		return "", fmt.Errorf(
			"%w: profile name %q has to start with a letter and may only "+
				"contain alphanumeric characters, '-' and '_'",
			errInvalidIdentifier, sp.GetName(),
		)
	}

	inherits := make([]string, 0, len(systemInherits)+len(objInherits))
	inherits = append(inherits, systemInherits...)

	for _, inherit := range objInherits {
		inherits = append(inherits, inherit.GetPolicyName())
	}

	for _, inherit := range inherits {
		if err := validateIdentifier("inherited policy", inherit); err != nil {
			return "", err
		}
	}

	cilbuilder := strings.Builder{}
	cilbuilder.WriteString(getCILStart(sp))

	// All templates must inherit from the system container. Without it, the
	// policy will not be loaded if it uses e.g. net_container or any other
	// template, because only the container template includes a "process"
	// definition. A profile inheriting other profile objects gets it through
	// them instead: those inherit the system container themselves, and
	// inheriting it twice would declare "process" twice. This assumes raw
	// profiles used as inherits do the same.
	if len(objInherits) == 0 {
		cilbuilder.WriteString(getCILInheritline(systemContainerInherit))
	}

	for _, inherit := range systemInherits {
		if inherit == systemContainerInherit {
			// Either written above or inherited through the profile objects.
			continue
		}

		cilbuilder.WriteString(getCILInheritline(inherit))
	}

	for _, inherit := range objInherits {
		cilbuilder.WriteString(getCILInheritline(inherit.GetPolicyName()))
	}

	if sp.Spec.Mode == selinuxprofileapi.SelinuxModePermissive {
		cilbuilder.WriteString(typePermissive)
		cilbuilder.WriteString("\n")
	}

	deniedOpts := deniedOptionsFromOpts(options)

	for _, ttype := range selinuxprofileapi.SortLabelKeys(sp.Spec.Allow) {
		for _, tclass := range selinuxprofileapi.SortObjectClassKeys(sp.Spec.Allow[ttype]) {
			if err := validateSemanticRule(
				deniedOpts,
				ttype,
				tclass,
				sp.Spec.Allow[ttype][tclass],
			); err != nil {
				return "", fmt.Errorf("invalid semantic rule for type %q, class %q: %w",
					ttype, tclass, err)
			}

			cilbuilder.WriteString(getCILAllowLine(sp, ttype, tclass, sp.Spec.Allow[ttype][tclass]))
		}
	}

	cilbuilder.WriteString(getCILEnd())

	return cilbuilder.String(), nil
}

// validateIdentifier returns an error if the value cannot be written into a
// CIL policy as a single identifier.
func validateIdentifier(kind, value string) error {
	if !identifierRegexp.MatchString(value) {
		return fmt.Errorf(
			"%w: %s %q may only contain alphanumeric characters, '.', '-' and '_'",
			errInvalidIdentifier, kind, value,
		)
	}

	return nil
}

func validateSemanticRule(opts *deniedOptions, ttype selinuxprofileapi.LabelKey,
	class selinuxprofileapi.ObjectClassKey,
	perms selinuxprofileapi.PermissionSet,
) error {
	// The denylists are compared by exact string, so the identifiers have to
	// be validated first. Otherwise, for example, " security" would bypass
	// the denied "security" class and still be parsed as that class.
	if ttype != selinuxprofileapi.AllowSelf {
		if err := validateIdentifier("type", ttype.String()); err != nil {
			return err
		}
	}

	if err := validateIdentifier("class", class.String()); err != nil {
		return err
	}

	for _, perm := range perms {
		if err := validateIdentifier("permission", perm); err != nil {
			return err
		}

		if _, ok := permissionKeywords[perm]; ok {
			return fmt.Errorf("%w: permission %q is a CIL keyword", errInvalidIdentifier, perm)
		}
	}

	// CIL resolves a name with leading dots, for example ".kernel_t", to the
	// symbol in the global namespace, so the names are compared with the
	// denylists without their empty dot separated components, see
	// globalName.
	if _, ok := opts.deniedTypes[globalName(ttype.String())]; ok {
		return fmt.Errorf("type %s is denied", ttype)
	}

	if _, ok := opts.deniedClasses[globalName(class.String())]; ok {
		return fmt.Errorf("class %s is denied", class)
	}

	for _, perm := range perms {
		if _, ok := opts.deniedPermissions[globalName(perm)]; ok {
			return fmt.Errorf("permission %s is denied", perm)
		}
	}

	return nil
}

// globalName returns the name without its empty dot separated components. CIL
// resolves a name with a leading dot in the global namespace and ignores the
// empty components of it, so ".kernel_t", ".kernel_t." and "..kernel_t.." all
// name kernel_t.
func globalName(name string) string {
	return strings.Join(slices.DeleteFunc(strings.Split(name, "."), func(part string) bool {
		return part == ""
	}), ".")
}

func getCILStart(sp *selinuxprofileapi.SelinuxProfile) string {
	return fmt.Sprintf("(block %s\n", sp.GetName())
}

func getCILInheritline(i string) string {
	return fmt.Sprintf("(blockinherit %s)\n", i)
}

func getCILAllowLine(
	sp *selinuxprofileapi.SelinuxProfile,
	ttype selinuxprofileapi.LabelKey,
	tclass selinuxprofileapi.ObjectClassKey,
	perms selinuxprofileapi.PermissionSet,
) string {
	ttypeFinal := ttype.String()
	if ttype == selinuxprofileapi.AllowSelf {
		ttypeFinal = sp.GetPolicyUsage()
	}

	uniquePerms := sets.New(perms...).UnsortedList()
	sort.Strings(uniquePerms)

	return fmt.Sprintf(
		"(allow process %s ( %s ( %s )))\n",
		ttypeFinal,
		tclass,
		strings.Join(uniquePerms, " "),
	)
}

func getCILEnd() string {
	return ")\n"
}
