/*
Copyright 2026 The Kubernetes Authors.

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
	"github.com/saschagrunert/security-profiles-merger/apparmor"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

func abstractToMergerProfile(a *apparmorprofileapi.AppArmorAbstract) *apparmor.Profile {
	p := &apparmor.Profile{}

	if a.Executable != nil {
		p.Executable = &apparmor.ExecutableRules{
			AllowedExecutables: a.Executable.AllowedExecutables,
			AllowedLibraries:   a.Executable.AllowedLibraries,
		}
	}

	if a.Filesystem != nil {
		p.Filesystem = &apparmor.FilesystemRules{
			ReadOnlyPaths:  a.Filesystem.ReadOnlyPaths,
			WriteOnlyPaths: a.Filesystem.WriteOnlyPaths,
			ReadWritePaths: a.Filesystem.ReadWritePaths,
		}
	}

	if a.Network != nil {
		p.Network = &apparmor.NetworkRules{
			AllowRaw: a.Network.AllowRaw,
		}

		if a.Network.Protocols != nil {
			p.Network.Protocols = &apparmor.AllowedProtocols{
				AllowTCP: a.Network.Protocols.AllowTCP,
				AllowUDP: a.Network.Protocols.AllowUDP,
			}
		}
	}

	if a.Capability != nil {
		p.Capabilities = &apparmor.CapabilityRules{
			AllowedCapabilities: a.Capability.AllowedCapabilities,
		}
	}

	return p
}

func mergerProfileToAbstract(p *apparmor.Profile) apparmorprofileapi.AppArmorAbstract {
	a := apparmorprofileapi.AppArmorAbstract{}

	if p.Executable != nil {
		a.Executable = &apparmorprofileapi.AppArmorExecutablesRules{
			AllowedExecutables: p.Executable.AllowedExecutables,
			AllowedLibraries:   p.Executable.AllowedLibraries,
		}
	}

	if p.Filesystem != nil {
		a.Filesystem = &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths:  p.Filesystem.ReadOnlyPaths,
			WriteOnlyPaths: p.Filesystem.WriteOnlyPaths,
			ReadWritePaths: p.Filesystem.ReadWritePaths,
		}
	}

	if p.Network != nil {
		a.Network = &apparmorprofileapi.AppArmorNetworkRules{
			AllowRaw: p.Network.AllowRaw,
		}

		if p.Network.Protocols != nil {
			a.Network.Protocols = &apparmorprofileapi.AppArmorAllowedProtocols{
				AllowTCP: p.Network.Protocols.AllowTCP,
				AllowUDP: p.Network.Protocols.AllowUDP,
			}
		}
	}

	if p.Capabilities != nil {
		a.Capability = &apparmorprofileapi.AppArmorCapabilityRules{
			AllowedCapabilities: p.Capabilities.AllowedCapabilities,
		}
	}

	return a
}
