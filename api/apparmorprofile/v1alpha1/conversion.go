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

package v1alpha1

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	apparmorprofilev1 "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
)

func (src *AppArmorProfile) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*apparmorprofilev1.AppArmorProfile)
	if !ok {
		return fmt.Errorf("expected *apparmorprofilev1.AppArmorProfile, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.State = profilebasev1.SpecState(src.Spec.State)
	dst.Spec.Mode = apparmorprofilev1.AppArmorMode(src.Spec.Mode)

	if src.Spec.Abstract.Executable != nil {
		dst.Spec.Abstract.Executable = &apparmorprofilev1.AppArmorExecutablesRules{
			AllowedExecutables: src.Spec.Abstract.Executable.AllowedExecutables,
			AllowedLibraries:   src.Spec.Abstract.Executable.AllowedLibraries,
		}
	}

	if src.Spec.Abstract.Filesystem != nil {
		dst.Spec.Abstract.Filesystem = &apparmorprofilev1.AppArmorFsRules{
			ReadOnlyPaths:  src.Spec.Abstract.Filesystem.ReadOnlyPaths,
			WriteOnlyPaths: src.Spec.Abstract.Filesystem.WriteOnlyPaths,
			ReadWritePaths: src.Spec.Abstract.Filesystem.ReadWritePaths,
		}
	}

	if src.Spec.Abstract.Network != nil {
		dst.Spec.Abstract.Network = &apparmorprofilev1.AppArmorNetworkRules{
			AllowRaw: src.Spec.Abstract.Network.AllowRaw,
		}
		if src.Spec.Abstract.Network.Protocols != nil {
			dst.Spec.Abstract.Network.Protocols = &apparmorprofilev1.AppArmorAllowedProtocols{
				AllowTCP: src.Spec.Abstract.Network.Protocols.AllowTCP,
				AllowUDP: src.Spec.Abstract.Network.Protocols.AllowUDP,
			}
		}
	}

	if src.Spec.Abstract.Capability != nil {
		dst.Spec.Abstract.Capability = &apparmorprofilev1.AppArmorCapabilityRules{
			AllowedCapabilities: src.Spec.Abstract.Capability.AllowedCapabilities,
		}
	}

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1.ProfileState(src.Status.Status)

	return nil
}

func (dst *AppArmorProfile) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*apparmorprofilev1.AppArmorProfile)
	if !ok {
		return fmt.Errorf("expected *apparmorprofilev1.AppArmorProfile, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.State = profilebasev1alpha1.SpecState(src.Spec.State)
	dst.Spec.Mode = AppArmorMode(src.Spec.Mode)

	if src.Spec.Abstract.Executable != nil {
		dst.Spec.Abstract.Executable = &AppArmorExecutablesRules{
			AllowedExecutables: src.Spec.Abstract.Executable.AllowedExecutables,
			AllowedLibraries:   src.Spec.Abstract.Executable.AllowedLibraries,
		}
	}

	if src.Spec.Abstract.Filesystem != nil {
		dst.Spec.Abstract.Filesystem = &AppArmorFsRules{
			ReadOnlyPaths:  src.Spec.Abstract.Filesystem.ReadOnlyPaths,
			WriteOnlyPaths: src.Spec.Abstract.Filesystem.WriteOnlyPaths,
			ReadWritePaths: src.Spec.Abstract.Filesystem.ReadWritePaths,
		}
	}

	if src.Spec.Abstract.Network != nil {
		dst.Spec.Abstract.Network = &AppArmorNetworkRules{
			AllowRaw: src.Spec.Abstract.Network.AllowRaw,
		}
		if src.Spec.Abstract.Network.Protocols != nil {
			dst.Spec.Abstract.Network.Protocols = &AppArmorAllowedProtocols{
				AllowTCP: src.Spec.Abstract.Network.Protocols.AllowTCP,
				AllowUDP: src.Spec.Abstract.Network.Protocols.AllowUDP,
			}
		}
	}

	if src.Spec.Abstract.Capability != nil {
		dst.Spec.Abstract.Capability = &AppArmorCapabilityRules{
			AllowedCapabilities: src.Spec.Abstract.Capability.AllowedCapabilities,
		}
	}

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1alpha1.ProfileState(src.Status.Status)

	return nil
}
