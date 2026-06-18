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

package translator

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

const (
	typePermissive         = "(typepermissive process)"
	systemContainerInherit = "container"
)

// Safe Defaults: Hardcoded denylists to prevent critical privilege escalation.
var (
	// deniedTypes prevents access to critical hosts assets.
	deniedTypes = map[string]struct{}{
		"kernel_t":   {}, // Core kernel structures
		"kmem_t":     {}, // Kernel memory
		"security_t": {}, // SELinux fs
		"shadow_t":   {}, // /etc/shadow
	}

	// deniedClasses prevents manipulation of the SELinux system itself.
	deniedClasses = map[string]struct{}{
		"capability": {}, // Linux capabilities
		"security":   {}, // Allows managing SELinux state
		"system":     {}, // Core system operations
	}

	// deniedPermissions prevents hostile actions on otherwise standard classes.
	deniedPermissions = map[string]struct{}{
		"load_policy": {}, // Can rewrite SELinux rules
		"mac_admin":   {},
		"mounton":     {},
		"relabelto":   {}, // Can hijack other containers' files
		"setbool":     {},
		"setenforce":  {}, // Can disable SELinux
		"setsecparam": {},
	}
)

func Object2CIL(
	systemInherits []string,
	objInherits []selinuxprofileapi.SelinuxProfileObject,
	sp *selinuxprofileapi.SelinuxProfile,
) (string, error) {
	cilbuilder := strings.Builder{}
	cilbuilder.WriteString(getCILStart(sp))

	// all templates must inherit from the system container. Without explicitly
	// inheriting from the system container, the policy will not be loaded
	// if it uses e.g. net_container or any other template because only the
	// container template includes a "process" definition unless it is inhrienting
	// another selinuxProfile object because the system container is already being
	// inherited in that case.
	if len(objInherits) == 0 {
		cilbuilder.WriteString(getCILInheritline(systemContainerInherit))
	}

	for _, inherit := range systemInherits {
		if inherit == systemContainerInherit {
			// already appended above
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

	for _, ttype := range selinuxprofileapi.SortLabelKeys(sp.Spec.Allow) {
		for _, tclass := range selinuxprofileapi.SortObjectClassKeys(sp.Spec.Allow[ttype]) {
			if err := validateSematicRule(ttype, tclass, sp.Spec.Allow[ttype][tclass]); err != nil {
				return "", fmt.Errorf("invalid semantic rule for type %s, class %s: %w",
					ttype, tclass, err)
			}

			cilbuilder.WriteString(getCILAllowLine(sp, ttype, tclass, sp.Spec.Allow[ttype][tclass]))
		}
	}

	cilbuilder.WriteString(getCILEnd())

	return cilbuilder.String(), nil
}

func validateSematicRule(ttype selinuxprofileapi.LabelKey,
	class selinuxprofileapi.ObjectClassKey,
	perms selinuxprofileapi.PermissionSet,
) error {
	if _, ok := deniedTypes[ttype.String()]; ok {
		return fmt.Errorf("type %s is denied", ttype)
	}

	if _, ok := deniedClasses[class.String()]; ok {
		return fmt.Errorf("class %s is denied", class)
	}

	for _, perm := range perms {
		if _, ok := deniedPermissions[perm]; ok {
			return fmt.Errorf("permission %s is denied", perm)
		}
	}

	return nil
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

	return fmt.Sprintf("(allow process %s ( %s ( %s )))\n", ttypeFinal, tclass, strings.Join(uniquePerms, " "))
}

func getCILEnd() string {
	return ")\n"
}
