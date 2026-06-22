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

import (
	"fmt"
	"strings"
)

// String returns a human-readable representation of the profile.
func (p Profile) String() string {
	var parts []string

	if p.Executable != nil {
		parts = append(parts, p.Executable.String())
	}

	if p.Filesystem != nil {
		parts = append(parts, p.Filesystem.String())
	}

	if p.Network != nil {
		parts = append(parts, p.Network.String())
	}

	if p.Capabilities != nil {
		parts = append(parts, p.Capabilities.String())
	}

	return fmt.Sprintf("Profile{%s}", strings.Join(parts, " "))
}

// String returns a human-readable representation of the executable rules.
func (e ExecutableRules) String() string {
	var parts []string

	if len(e.AllowedExecutables) > 0 {
		parts = append(parts, "exec:"+strings.Join(e.AllowedExecutables, ","))
	}

	if len(e.AllowedLibraries) > 0 {
		parts = append(parts, "lib:"+strings.Join(e.AllowedLibraries, ","))
	}

	return strings.Join(parts, " ")
}

// String returns a human-readable representation of the filesystem rules.
func (f FilesystemRules) String() string {
	var parts []string

	if len(f.ReadOnlyPaths) > 0 {
		parts = append(parts, "r:"+strings.Join(f.ReadOnlyPaths, ","))
	}

	if len(f.WriteOnlyPaths) > 0 {
		parts = append(parts, "w:"+strings.Join(f.WriteOnlyPaths, ","))
	}

	if len(f.ReadWritePaths) > 0 {
		parts = append(parts, "rw:"+strings.Join(f.ReadWritePaths, ","))
	}

	return strings.Join(parts, " ")
}

// String returns a human-readable representation of the network rules.
func (n NetworkRules) String() string {
	var parts []string

	if n.AllowRaw != nil && *n.AllowRaw {
		parts = append(parts, "raw")
	}

	if n.Protocols != nil {
		if n.Protocols.AllowTCP != nil && *n.Protocols.AllowTCP {
			parts = append(parts, "tcp")
		}

		if n.Protocols.AllowUDP != nil && *n.Protocols.AllowUDP {
			parts = append(parts, "udp")
		}
	}

	return "net:" + strings.Join(parts, ",")
}

// String returns a human-readable representation of the capability rules.
func (c CapabilityRules) String() string {
	return "caps:" + strings.Join(c.AllowedCapabilities, ",")
}
