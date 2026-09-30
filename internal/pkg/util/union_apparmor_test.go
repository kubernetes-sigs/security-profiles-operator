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

package util

import (
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

// UnionAppArmor decides what a merged AppArmor profile ends up allowing, so a
// wrong merge silently produces an over- or under-permissive profile.
func TestUnionAppArmor(t *testing.T) {
	t.Parallel()

	t.Run("empty profiles merge to an empty profile", func(t *testing.T) {
		t.Parallel()

		got, err := UnionAppArmor(
			&apparmorprofileapi.AppArmorAbstract{},
			&apparmorprofileapi.AppArmorAbstract{},
		)
		require.NoError(t, err)
		require.Equal(t, apparmorprofileapi.AppArmorAbstract{}, got)
	})

	t.Run("executables are unioned", func(t *testing.T) {
		t.Parallel()

		got, err := UnionAppArmor(
			&apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/bin/sh"},
				},
			},
			&apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/bin/ls"},
				},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, got.Executable)
		require.ElementsMatch(t,
			[]string{"/bin/sh", "/bin/ls"}, got.Executable.AllowedExecutables)
	})

	t.Run("filesystem paths are unioned without duplicates", func(t *testing.T) {
		t.Parallel()

		got, err := UnionAppArmor(
			&apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/etc/passwd", "/etc/group"},
				},
			},
			&apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths:  []string{"/etc/passwd"},
					ReadWritePaths: []string{"/tmp"},
				},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, got.Filesystem)
		require.ElementsMatch(t,
			[]string{"/etc/passwd", "/etc/group"}, got.Filesystem.ReadOnlyPaths)
		require.ElementsMatch(t, []string{"/tmp"}, got.Filesystem.ReadWritePaths)
	})

	t.Run("network permissions are unioned", func(t *testing.T) {
		t.Parallel()

		got, err := UnionAppArmor(
			&apparmorprofileapi.AppArmorAbstract{
				Network: &apparmorprofileapi.AppArmorNetworkRules{
					Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{
						AllowTCP: new(true),
					},
				},
			},
			&apparmorprofileapi.AppArmorAbstract{
				Network: &apparmorprofileapi.AppArmorNetworkRules{
					AllowRaw: new(true),
					Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{
						AllowUDP: new(true),
					},
				},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, got.Network)
		require.Equal(t, new(true), got.Network.AllowRaw)
		require.NotNil(t, got.Network.Protocols)
		require.Equal(t, new(true), got.Network.Protocols.AllowTCP)
		require.Equal(t, new(true), got.Network.Protocols.AllowUDP)
	})

	t.Run("paths with variables are unioned", func(t *testing.T) {
		t.Parallel()

		base := &apparmorprofileapi.AppArmorAbstract{
			Executable: &apparmorprofileapi.AppArmorExecutablesRules{
				AllowedExecutables: []string{"/bin/sh", "/proc/@{pid}/exe"},
			},
			Filesystem: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths: []string{
					"/etc/passwd", "/proc/@{pid}/maps", "/proc/@{pid}/status",
				},
				WriteOnlyPaths: []string{"/proc/@{pid}/task/@{tid}/comm"},
			},
		}
		additions := &apparmorprofileapi.AppArmorAbstract{
			Executable: &apparmorprofileapi.AppArmorExecutablesRules{
				AllowedExecutables: []string{"/proc/@{pid}/exe"},
			},
			Filesystem: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/proc/@{pid}/task/@{tid}/comm", "/@{pid}/mounts"},
				WriteOnlyPaths: []string{"/proc/@{pid}/status"},
				ReadWritePaths: []string{"/tmp"},
			},
		}

		got, err := UnionAppArmor(base, additions)
		require.NoError(t, err)
		require.Equal(t, apparmorprofileapi.AppArmorAbstract{
			Executable: &apparmorprofileapi.AppArmorExecutablesRules{
				AllowedExecutables: []string{"/bin/sh", "/proc/@{pid}/exe"},
			},
			Filesystem: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths: []string{
					"/@{pid}/mounts", "/etc/passwd", "/proc/@{pid}/maps",
				},
				ReadWritePaths: []string{
					"/proc/@{pid}/status", "/proc/@{pid}/task/@{tid}/comm", "/tmp",
				},
			},
		}, got)

		// The inputs are left as they are.
		require.Equal(t, []string{
			"/etc/passwd", "/proc/@{pid}/maps", "/proc/@{pid}/status",
		}, base.Filesystem.ReadOnlyPaths)
		require.Equal(t,
			[]string{"/proc/@{pid}/exe"}, additions.Executable.AllowedExecutables)
	})

	t.Run("paths with variables are merged into missing sections", func(t *testing.T) {
		t.Parallel()

		got, err := UnionAppArmor(
			&apparmorprofileapi.AppArmorAbstract{},
			&apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedLibraries: []string{"/proc/@{pid}/lib.so"},
				},
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"/proc/@{pid}/attr/current"},
				},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, got.Executable)
		require.Equal(t, []string{"/proc/@{pid}/lib.so"}, got.Executable.AllowedLibraries)
		require.NotNil(t, got.Filesystem)
		require.Equal(t,
			[]string{"/proc/@{pid}/attr/current"}, got.Filesystem.ReadWritePaths)
	})

	t.Run("merging with an empty profile keeps the other side", func(t *testing.T) {
		t.Parallel()

		base := &apparmorprofileapi.AppArmorAbstract{
			Executable: &apparmorprofileapi.AppArmorExecutablesRules{
				AllowedExecutables: []string{"/bin/sh"},
			},
		}

		got, err := UnionAppArmor(base, &apparmorprofileapi.AppArmorAbstract{})
		require.NoError(t, err)
		require.NotNil(t, got.Executable)
		require.Equal(t, []string{"/bin/sh"}, got.Executable.AllowedExecutables)
	})
}

func TestUnionAppArmorPtrace(t *testing.T) {
	t.Parallel()

	rules := func(peer string, access ...apparmorprofileapi.AppArmorPtraceAccess) *apparmorprofileapi.AppArmorPtraceRules {
		return &apparmorprofileapi.AppArmorPtraceRules{AllowedAccess: access, Peer: peer}
	}

	for _, tc := range []struct {
		name        string
		left, right *apparmorprofileapi.AppArmorPtraceRules
		want        *apparmorprofileapi.AppArmorPtraceRules
	}{
		{name: "none"},
		{
			name: "only left",
			left: rules("peer", apparmorprofileapi.AppArmorPtraceAccessRead),
			want: rules("peer", apparmorprofileapi.AppArmorPtraceAccessRead),
		},
		{
			name: "only right",
			right: rules("peer", apparmorprofileapi.AppArmorPtraceAccessTrace,
				apparmorprofileapi.AppArmorPtraceAccessRead, apparmorprofileapi.AppArmorPtraceAccessRead),
			want: rules("peer", apparmorprofileapi.AppArmorPtraceAccessRead, apparmorprofileapi.AppArmorPtraceAccessTrace),
		},
		{
			name: "same peer",
			left: rules("peer", apparmorprofileapi.AppArmorPtraceAccessTrace, apparmorprofileapi.AppArmorPtraceAccessRead),
			right: rules("peer", apparmorprofileapi.AppArmorPtraceAccessRead,
				apparmorprofileapi.AppArmorPtraceAccessReadBy),
			want: rules("peer", apparmorprofileapi.AppArmorPtraceAccessRead,
				apparmorprofileapi.AppArmorPtraceAccessReadBy, apparmorprofileapi.AppArmorPtraceAccessTrace),
		},
		{
			// A rule for every peer allows what both rules allow.
			name:  "different peers",
			left:  rules("a", apparmorprofileapi.AppArmorPtraceAccessRead),
			right: rules("b", apparmorprofileapi.AppArmorPtraceAccessTrace),
			want:  rules("", apparmorprofileapi.AppArmorPtraceAccessRead, apparmorprofileapi.AppArmorPtraceAccessTrace),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := UnionAppArmor(
				&apparmorprofileapi.AppArmorAbstract{Ptrace: tc.left},
				&apparmorprofileapi.AppArmorAbstract{Ptrace: tc.right},
			)
			require.NoError(t, err)
			require.Equal(t, tc.want, got.Ptrace)
		})
	}
}

// The API only accepts lower case capabilities, while the merger returns them
// upper-cased.
func TestUnionAppArmorCapabilitiesLowerCase(t *testing.T) {
	t.Parallel()

	got, err := UnionAppArmor(
		&apparmorprofileapi.AppArmorAbstract{
			Capability: &apparmorprofileapi.AppArmorCapabilityRules{
				AllowedCapabilities: []string{"net_raw", "sys_admin"},
			},
		},
		&apparmorprofileapi.AppArmorAbstract{
			Capability: &apparmorprofileapi.AppArmorCapabilityRules{
				AllowedCapabilities: []string{"NET_ADMIN", "net_raw"},
			},
		},
	)
	require.NoError(t, err)
	require.NotNil(t, got.Capability)
	require.Equal(
		t,
		[]string{"net_admin", "net_raw", "sys_admin"},
		got.Capability.AllowedCapabilities,
	)
}

func TestLowerCapabilities(t *testing.T) {
	t.Parallel()

	require.Nil(t, LowerCapabilities(nil))
	require.Equal(t,
		[]string{"net_admin", "netx", "sys_admin"},
		LowerCapabilities([]string{"SYS_ADMIN", "NETX", "NET_ADMIN", "net_admin"}),
	)
}
