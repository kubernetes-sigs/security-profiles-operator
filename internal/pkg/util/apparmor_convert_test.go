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
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

func TestAppArmorRoundTrip(t *testing.T) {
	t.Parallel()

	input := apparmorprofileapi.AppArmorAbstract{
		Executable: &apparmorprofileapi.AppArmorExecutablesRules{
			AllowedExecutables: []string{"/usr/bin/bash", "/usr/bin/python"},
			AllowedLibraries:   []string{"/usr/lib/libc.so"},
		},
		Filesystem: &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths:  []string{"/etc/config"},
			WriteOnlyPaths: []string{"/var/log"},
			ReadWritePaths: []string{"/tmp"},
		},
		Network: &apparmorprofileapi.AppArmorNetworkRules{
			AllowRaw: new(true),
			Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{
				AllowTCP: new(true),
				AllowUDP: new(false),
			},
		},
		Capability: &apparmorprofileapi.AppArmorCapabilityRules{
			AllowedCapabilities: []string{"NET_ADMIN", "SYS_TIME"},
		},
	}

	profile := abstractToMergerProfile(&input)
	roundTripped := mergerProfileToAbstract(profile)

	require.Equal(t, input, roundTripped)
}

func TestAppArmorRoundTripNilFields(t *testing.T) {
	t.Parallel()

	input := apparmorprofileapi.AppArmorAbstract{}

	profile := abstractToMergerProfile(&input)
	roundTripped := mergerProfileToAbstract(profile)

	require.Equal(t, input, roundTripped)
}

func TestAppArmorRoundTripPartialNetwork(t *testing.T) {
	t.Parallel()

	input := apparmorprofileapi.AppArmorAbstract{
		Network: &apparmorprofileapi.AppArmorNetworkRules{
			AllowRaw: new(false),
		},
	}

	profile := abstractToMergerProfile(&input)
	roundTripped := mergerProfileToAbstract(profile)

	require.Equal(t, input, roundTripped)
}

func TestAppArmorRoundTripCapabilityOnly(t *testing.T) {
	t.Parallel()

	input := apparmorprofileapi.AppArmorAbstract{
		Capability: &apparmorprofileapi.AppArmorCapabilityRules{
			AllowedCapabilities: []string{"CHOWN"},
		},
	}

	profile := abstractToMergerProfile(&input)
	roundTripped := mergerProfileToAbstract(profile)

	require.Equal(t, input, roundTripped)
}
