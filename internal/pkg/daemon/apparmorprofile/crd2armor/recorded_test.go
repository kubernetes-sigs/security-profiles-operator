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
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

func TestAbstractFromRecording(t *testing.T) {
	t.Parallel()

	enabled := true

	for _, tc := range []struct {
		name     string
		recorded RecordedAccess
		want     apparmorprofileapi.AppArmorAbstract
	}{
		{
			name: "nothing recorded leaves every section out",
		},
		{
			name: "paths get sorted and empty lists stay out",
			recorded: RecordedAccess{
				AllowedLibraries: []string{"/lib/b.so", "/lib/a.so"},
				ReadOnlyPaths:    []string{"/etc/b", "/etc/a"},
			},
			want: apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedLibraries: []string{"/lib/a.so", "/lib/b.so"},
				},
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/etc/a", "/etc/b"},
				},
			},
		},
		{
			name:     "raw sockets without protocols",
			recorded: RecordedAccess{UseRaw: true},
			want: apparmorprofileapi.AppArmorAbstract{
				Network: &apparmorprofileapi.AppArmorNetworkRules{AllowRaw: &enabled},
			},
		},
		{
			name:     "protocols without raw sockets",
			recorded: RecordedAccess{UseUDP: true},
			want: apparmorprofileapi.AppArmorAbstract{
				Network: &apparmorprofileapi.AppArmorNetworkRules{
					Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{AllowUDP: &enabled},
				},
			},
		},
		{
			name:     "capabilities keep their order",
			recorded: RecordedAccess{Capabilities: []string{"sys_admin", "chown"}},
			want: apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{"sys_admin", "chown"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recorded := tc.recorded
			require.Equal(t, tc.want, AbstractFromRecording(&recorded))
		})
	}
}

// The recorded lists are copied, so the profile does not change with them.
func TestAbstractFromRecordingCopies(t *testing.T) {
	t.Parallel()

	recorded := RecordedAccess{
		ReadWritePaths: []string{"/tmp"},
		Capabilities:   []string{"chown"},
	}
	abstract := AbstractFromRecording(&recorded)

	recorded.ReadWritePaths[0] = "/changed"
	recorded.Capabilities[0] = "changed"

	require.Equal(t, []string{"/tmp"}, abstract.Filesystem.ReadWritePaths)
	require.Equal(t, []string{"chown"}, abstract.Capability.AllowedCapabilities)
}
