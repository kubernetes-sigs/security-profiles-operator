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

package v1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func newProfile(namespace, name string) *SeccompProfile {
	return &SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
	}
}

func TestGetProfileFile(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		profileName string
		want        string
	}{
		"appends the json extension":    {"profile", "profile" + ExtJSON},
		"keeps an existing extension":   {"profile" + ExtJSON, "profile" + ExtJSON},
		"only matches the suffix":       {"profile.json.bak", "profile.json.bak" + ExtJSON},
		"handles an empty profile name": {"", ExtJSON},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, newProfile("ns", tc.profileName).GetProfileFile())
		})
	}
}

// TestGetProfilePathIsContained asserts that neither the namespace nor the
// profile name can escape the profiles root, since both are user controlled.
func TestGetProfilePathIsContained(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		namespace   string
		profileName string
	}{
		"plain":                  {"my-ns", "my-profile"},
		"traversal in namespace": {"../../../../etc", "my-profile"},
		"traversal in name":      {"my-ns", "../../../../etc/passwd"},
		"traversal in both":      {"../..", "../../etc/passwd"},
		"absolute namespace":     {"/etc", "my-profile"},
		"absolute name":          {"my-ns", "/etc/passwd"},
		"empty namespace":        {"", "my-profile"},
		"dot namespace":          {".", "my-profile"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sp := newProfile(tc.namespace, tc.profileName)

			for root, got := range map[string]string{
				config.ProfilesRootPath(): sp.GetProfilePath(),
				config.OperatorRoot:       sp.GetProfileOperatorPath(),
			} {
				require.True(t, strings.HasPrefix(got, root+"/"),
					"%q must stay below %q", got, root)
				require.NotContains(t, got, "..", "%q must not contain a traversal", got)
			}
		})
	}
}

func TestGetProfilePath(t *testing.T) {
	t.Parallel()

	sp := newProfile("my-ns", "my-profile")

	require.Equal(t,
		config.ProfilesRootPath()+"/my-ns/my-profile"+ExtJSON,
		sp.GetProfilePath())
	require.Equal(t,
		config.OperatorRoot+"/my-ns/my-profile"+ExtJSON,
		sp.GetProfileOperatorPath())
}

// TestGetProfilePathEmptyNamespace pins that an empty or dotted namespace still
// collapses the way path.Join always handled it, rather than growing a segment.
func TestGetProfilePathEmptyNamespace(t *testing.T) {
	t.Parallel()

	want := config.ProfilesRootPath() + "/my-profile" + ExtJSON

	require.Equal(t, want, newProfile("", "my-profile").GetProfilePath())
	require.Equal(t, want, newProfile(".", "my-profile").GetProfilePath())
}

func TestSetImplementationStatus(t *testing.T) {
	t.Parallel()

	sp := newProfile("my-ns", "my-profile")
	sp.SetImplementationStatus()

	require.Equal(t,
		strings.TrimPrefix(sp.GetProfilePath(), config.KubeletSeccompRootPath()+"/"),
		sp.Status.LocalhostProfile)
	require.NotContains(t, sp.Status.LocalhostProfile, config.KubeletSeccompRootPath())
}

func TestIsDisabledAndReconcilable(t *testing.T) {
	t.Parallel()

	enabled := newProfile("ns", "name")
	require.False(t, enabled.IsDisabled())
	require.False(t, enabled.IsPartial())
	require.True(t, enabled.IsReconcilable())

	disabled := newProfile("ns", "name")
	disabled.Spec.State = profilebasev1.SpecStateDisabled
	require.True(t, disabled.IsDisabled())
	require.False(t, disabled.IsReconcilable())

	partial := newProfile("ns", "name")
	partial.SetLabels(map[string]string{profilebasev1.ProfilePartialLabel: "true"})
	require.True(t, partial.IsPartial())
	require.False(t, partial.IsReconcilable())
}
