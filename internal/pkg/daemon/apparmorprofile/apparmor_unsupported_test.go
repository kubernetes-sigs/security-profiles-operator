//go:build !apparmor

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

package apparmorprofile

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

// Without AppArmor support in the build, every operation reports it instead
// of pretending to succeed.
func TestUnsupportedProfileManager(t *testing.T) {
	t.Parallel()

	manager := NewAppArmorProfileManager(logr.Discard())
	profile := &apparmorprofileapi.AppArmorProfile{}

	require.False(t, manager.Enabled())

	_, err := manager.InstallProfile(profile, false)
	require.ErrorIs(t, err, errAppArmorNotSupported)
	require.ErrorIs(t, manager.RemoveProfile(profile, true), errAppArmorNotSupported)

	_, err = loadProfile(logr.Discard(), "name", "content")
	require.ErrorIs(t, err, errAppArmorNotSupported)
	require.ErrorIs(t, removeProfile(logr.Discard(), "name", "path", true), errAppArmorNotSupported)
	require.False(t, checkProfileExist(logr.Discard(), "name"))
	require.False(t, profileManagedByUs(logr.Discard(), "path"))
}
