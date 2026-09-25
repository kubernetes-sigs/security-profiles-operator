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

package apparmor

// Profile represents a structured AppArmor profile for merge operations.
// This type mirrors the structure used by the Security Profiles Operator
// without depending on its CRD types.
//
// A nil field means the profile says nothing about that section, which to
// AppArmor denies everything the section covers. Intersect treats it as an
// explicit empty section (e.g. &CapabilityRules{}), so intersecting
// {caps: [NET_ADMIN]} with {caps: nil} yields [] like {caps: []} does. Union
// lets a nil section defer to the other profile, which grants the same as
// an empty one would; only the shape of the result differs.
type Profile struct {
	Executable   *ExecutableRules `json:"executable,omitempty"`
	Filesystem   *FilesystemRules `json:"filesystem,omitempty"`
	Network      *NetworkRules    `json:"network,omitempty"`
	Capabilities *CapabilityRules `json:"capability,omitempty"`
}

// ExecutableRules defines which executables and libraries may be run.
type ExecutableRules struct {
	AllowedExecutables []string `json:"allowedExecutables,omitempty"`
	AllowedLibraries   []string `json:"allowedLibraries,omitempty"`
}

// FilesystemRules defines file access permissions.
type FilesystemRules struct {
	ReadOnlyPaths  []string `json:"readOnlyPaths,omitempty"`
	WriteOnlyPaths []string `json:"writeOnlyPaths,omitempty"`
	ReadWritePaths []string `json:"readWritePaths,omitempty"`
}

// NetworkRules defines network access permissions.
type NetworkRules struct {
	AllowRaw  *bool             `json:"allowRaw,omitempty"`
	Protocols *AllowedProtocols `json:"allowedProtocols,omitempty"`
}

// AllowedProtocols defines which network protocols are permitted.
type AllowedProtocols struct {
	AllowTCP *bool `json:"allowTcp,omitempty"`
	AllowUDP *bool `json:"allowUdp,omitempty"`
}

// CapabilityRules defines which Linux capabilities are permitted.
//
// Names are compared case-insensitively, and the merge functions return them
// upper-cased ("CHOWN", "NET_ADMIN"). apparmor_parser accepts capability
// names in lower case only, so a consumer rendering these as
// "capability <name>," rules must lower-case each name first; written as the
// merge returns them, the profile does not load.
type CapabilityRules struct {
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}
