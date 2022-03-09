/*
Copyright 2022 The Kubernetes Authors.

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

package util

import (
	corev1 "k8s.io/api/core/v1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
)

// PatchSecurityContext patches a security context fields
// This avoids overwriting an existing value with a nil which is the case when using DeepCopy.
func PatchSecurityContext(base *corev1.SecurityContext, patch *corev1.SecurityContext) *corev1.SecurityContext {
	if patch == nil {
		return base
	}
	if patch.Capabilities != nil {
		base.Capabilities = patch.Capabilities.DeepCopy()
	}
	if patch.Privileged != nil {
		base.Privileged = new(bool)
		*base.Privileged = *patch.Privileged
	}
	if patch.SELinuxOptions != nil {
		base.SELinuxOptions = patch.SELinuxOptions.DeepCopy()
	}
	if patch.WindowsOptions != nil {
		base.WindowsOptions = patch.WindowsOptions.DeepCopy()
	}
	if patch.RunAsUser != nil {
		base.RunAsUser = new(int64)
		*base.RunAsUser = *patch.RunAsUser
	}
	if patch.RunAsGroup != nil {
		base.RunAsGroup = new(int64)
		*base.RunAsGroup = *patch.RunAsGroup
	}
	if patch.RunAsNonRoot != nil {
		base.RunAsNonRoot = new(bool)
		*base.RunAsNonRoot = *patch.RunAsNonRoot
	}
	if patch.ReadOnlyRootFilesystem != nil {
		base.ReadOnlyRootFilesystem = new(bool)
		*base.ReadOnlyRootFilesystem = *patch.ReadOnlyRootFilesystem
	}
	if patch.AllowPrivilegeEscalation != nil {
		base.AllowPrivilegeEscalation = new(bool)
		*base.AllowPrivilegeEscalation = *patch.AllowPrivilegeEscalation
	}
	if patch.ProcMount != nil {
		base.ProcMount = new(corev1.ProcMountType)
		*base.ProcMount = *patch.ProcMount
	}
	if patch.SeccompProfile != nil {
		base.SeccompProfile = patch.SeccompProfile.DeepCopy()
	}
	return base
}

// GetSecurityContext returns a security context with matches the container name or nil otherwise
func GetSecurityContext(securityContexts []spodv1alpha1.SecurityContext, name string) *corev1.SecurityContext {
	for _, sc := range securityContexts {
		if sc.ContainerName == name {
			return sc.SecurityContext
		}
	}
	return nil
}
