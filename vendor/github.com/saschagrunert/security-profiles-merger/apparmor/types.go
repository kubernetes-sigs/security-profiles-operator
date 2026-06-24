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
// Nil fields mean "unspecified" and defer to the other profile during merge.
// A non-nil field with empty contents (e.g. &CapabilityRules{}) means
// "explicitly no permissions". This distinction affects merge results:
// intersecting {caps: [NET_ADMIN]} with {caps: nil} yields [NET_ADMIN],
// while intersecting {caps: [NET_ADMIN]} with {caps: []} yields [].
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
	AllowTCP *bool `json:"allowTcp,omitempty"` //nolint:tagliatelle // matches SPO CRD
	AllowUDP *bool `json:"allowUdp,omitempty"` //nolint:tagliatelle // matches SPO CRD
}

// CapabilityRules defines which Linux capabilities are permitted.
type CapabilityRules struct {
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}
