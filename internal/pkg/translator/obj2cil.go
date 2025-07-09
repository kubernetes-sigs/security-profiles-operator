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

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

const (
	typePermissive         = "(typepermissive process)"
	systemContainerInherit = "container"
)

func Object2CIL(
	systemInherits []string,
	objInherits []selxv1alpha2.SelinuxProfileObject,
	sp *selxv1alpha2.SelinuxProfile,
) string {
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

	if sp.Spec.Permissive {
		cilbuilder.WriteString(typePermissive)
		cilbuilder.WriteString("\n")
	}

	for _, ttype := range selxv1alpha2.SortLabelKeys(sp.Spec.Allow) {
		for _, tclass := range selxv1alpha2.SortObjectClassKeys(sp.Spec.Allow[ttype]) {
			cilbuilder.WriteString(getCILAllowLine(sp, ttype, tclass, sp.Spec.Allow[ttype][tclass]))
		}
	}

	cilbuilder.WriteString(getCILEnd())

	return cilbuilder.String()
}

func getCILStart(sp *selxv1alpha2.SelinuxProfile) string {
	return fmt.Sprintf("(block %s_%s\n", sp.GetName(), sp.GetNamespace())
}

func getCILInheritline(i string) string {
	return fmt.Sprintf("(blockinherit %s)\n", i)
}

func getCILAllowLine(
	sp *selxv1alpha2.SelinuxProfile,
	ttype selxv1alpha2.LabelKey,
	tclass selxv1alpha2.ObjectClassKey,
	perms selxv1alpha2.PermissionSet,
) string {
	ttypeFinal := ttype.String()
	if ttype == selxv1alpha2.AllowSelf {
		ttypeFinal = sp.GetPolicyUsage()
	}

	uniquePerms := sets.New(perms...).UnsortedList()
	sort.Strings(uniquePerms)

	return fmt.Sprintf("(allow process %s ( %s ( %s )))\n", ttypeFinal, tclass, strings.Join(uniquePerms, " "))
}

func getCILEnd() string {
	return ")\n"
}
