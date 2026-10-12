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

package v1_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	spodv1 "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

func TestSelinuxEnabled(t *testing.T) {
	t.Parallel()

	spod := &spodv1.SecurityProfilesOperatorDaemon{}
	require.False(t, spod.SelinuxEnabled(false))
	require.True(t, spod.SelinuxEnabled(true), "enabled by default on OpenShift")

	spod.Spec.Selinux.Enable = new(false)
	require.False(t, spod.SelinuxEnabled(true))

	spod.Spec.Selinux.Enable = new(true)
	require.True(t, spod.SelinuxEnabled(false))
}

func TestAppArmorEnabled(t *testing.T) {
	t.Parallel()

	spod := &spodv1.SecurityProfilesOperatorDaemon{}
	require.False(t, spod.AppArmorEnabled())

	spod.Spec.EnableAppArmor = new(false)
	require.False(t, spod.AppArmorEnabled())

	spod.Spec.EnableAppArmor = new(true)
	require.True(t, spod.AppArmorEnabled())
}
