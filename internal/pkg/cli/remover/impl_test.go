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

package remover

import (
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

// ownershipManager records the ownership evidence of a removal.
type ownershipManager struct {
	ownedByUs *bool
}

func (*ownershipManager) Enabled() bool { return true }

func (*ownershipManager) KnownUnsupported() bool { return false }

func (*ownershipManager) InstallProfile(profilebaseapi.StatusBaseUser, bool) (bool, error) {
	return false, nil
}

func (m *ownershipManager) RemoveProfile(
	_ profilebaseapi.StatusBaseUser,
	ownedByUs bool,
) (bool, error) {
	m.ownedByUs = &ownedByUs

	return true, nil
}

func (*ownershipManager) ProfileInstalled(profilebaseapi.StatusBaseUser) (bool, error) {
	return false, nil
}

// TestAppArmorRemoveProfileRequiresPolicyFile asserts that spoc remove only
// unloads a profile whose policy file proves it is ours, so that a profile file
// named like the default profile of a container runtime cannot unload it.
func TestAppArmorRemoveProfileRequiresPolicyFile(t *testing.T) {
	t.Parallel()

	manager := &ownershipManager{}

	removed, err := (&defaultImpl{}).AppArmorRemoveProfile(
		manager, &apparmorprofileapi.AppArmorProfile{},
	)
	require.NoError(t, err)
	require.True(t, removed)
	require.NotNil(t, manager.ownedByUs)
	require.False(t, *manager.ownedByUs)
}
