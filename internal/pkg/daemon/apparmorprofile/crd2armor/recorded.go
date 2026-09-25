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

package crd2armor

import (
	"slices"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

// RecordedAccess is what the BPF recorder observed a workload doing.
type RecordedAccess struct {
	AllowedExecutables []string
	AllowedLibraries   []string
	ReadOnlyPaths      []string
	WriteOnlyPaths     []string
	ReadWritePaths     []string
	UseRaw             bool
	UseTCP             bool
	UseUDP             bool
	Capabilities       []string
}

// AbstractFromRecording returns the abstract profile allowing the recorded
// access. Sections without any recorded access are left out.
func AbstractFromRecording(recorded *RecordedAccess) apparmorprofileapi.AppArmorAbstract {
	abstract := apparmorprofileapi.AppArmorAbstract{}

	if len(recorded.AllowedExecutables) != 0 || len(recorded.AllowedLibraries) != 0 {
		abstract.Executable = &apparmorprofileapi.AppArmorExecutablesRules{
			AllowedExecutables: sortedOrNil(recorded.AllowedExecutables),
			AllowedLibraries:   sortedOrNil(recorded.AllowedLibraries),
		}
	}

	if len(recorded.ReadOnlyPaths) != 0 || len(recorded.WriteOnlyPaths) != 0 ||
		len(recorded.ReadWritePaths) != 0 {
		abstract.Filesystem = &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths:  sortedOrNil(recorded.ReadOnlyPaths),
			WriteOnlyPaths: sortedOrNil(recorded.WriteOnlyPaths),
			ReadWritePaths: sortedOrNil(recorded.ReadWritePaths),
		}
	}

	if recorded.UseRaw || recorded.UseTCP || recorded.UseUDP {
		enabled := true
		network := apparmorprofileapi.AppArmorNetworkRules{}

		if recorded.UseRaw {
			network.AllowRaw = &enabled
		}

		if recorded.UseTCP || recorded.UseUDP {
			network.Protocols = &apparmorprofileapi.AppArmorAllowedProtocols{}

			if recorded.UseTCP {
				network.Protocols.AllowTCP = &enabled
			}

			if recorded.UseUDP {
				network.Protocols.AllowUDP = &enabled
			}
		}

		abstract.Network = &network
	}

	if len(recorded.Capabilities) != 0 {
		abstract.Capability = &apparmorprofileapi.AppArmorCapabilityRules{
			AllowedCapabilities: slices.Clone(recorded.Capabilities),
		}
	}

	return abstract
}

// sortedOrNil returns a sorted copy of paths, or nil if there are none, so
// that the empty lists stay out of the profile.
func sortedOrNil(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}

	sorted := slices.Clone(paths)
	slices.Sort(sorted)

	return sorted
}
