/*
Copyright 2021 The Kubernetes Authors.

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

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
)

func TestGenerateProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		complainMode   bool
		abstract       *apparmorprofileapi.AppArmorAbstract
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:         "EnforceModeWithDeny",
			complainMode: false,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: &[]string{"/etc/passwd"},
				},
			},
			mustContain: []string{
				"profile EnforceModeWithDeny flags=(enforce",
				"/etc/passwd r,",
				"deny /etc/passwd wlk,",
				"deny @{PROC}/* w,",
			},
		},
		{
			name:         "ComplainModeWithoutDeny",
			complainMode: true,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: &[]string{"/etc/passwd"},
				},
			},
			mustContain: []string{
				"profile ComplainModeWithoutDeny flags=(complain",
				"/etc/passwd r,",
			},
			mustNotContain: []string{
				"deny /etc/passwd wlk,",
				"deny @{PROC}/* w,",
				"audit /etc/passwd wlk,",
				"audit @{PROC}/* w,",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := GenerateProfile(tc.name, tc.complainMode, tc.abstract)
			require.NoError(t, err)

			for _, s := range tc.mustContain {
				require.Contains(t, got, s)
			}

			for _, s := range tc.mustNotContain {
				require.NotContains(t, got, s)
			}
		})
	}
}
