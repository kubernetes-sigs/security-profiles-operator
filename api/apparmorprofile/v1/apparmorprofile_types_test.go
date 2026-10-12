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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apparmorprofilev1 "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

func TestAppArmorProfileHelpers(t *testing.T) {
	t.Parallel()

	profile := &apparmorprofilev1.AppArmorProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "profile"},
	}
	require.Equal(t, "profile", profile.GetProfileName())
	require.Same(t, &profile.Status.StatusBase, profile.GetStatusBase())
	require.True(t, profile.IsReconcilable())

	// The status of AppArmor profiles has no implementation specific fields.
	before := profile.Status.DeepCopy()
	profile.SetImplementationStatus()
	require.Equal(t, before, &profile.Status)

	// The copy does not share the status with the profile.
	cp := profile.DeepCopyToStatusBaseIf()
	cp.GetStatusBase().Status = "Installed"
	require.Empty(t, profile.Status.Status)

	profile.Labels = map[string]string{profilebasev1.ProfilePartialLabel: "true"}
	require.True(t, profile.IsPartial())
	require.False(t, profile.IsReconcilable())

	profile.Labels = nil
	profile.Spec.State = profilebasev1.SpecStateDisabled
	require.True(t, profile.IsDisabled())
	require.False(t, profile.IsReconcilable())
}
