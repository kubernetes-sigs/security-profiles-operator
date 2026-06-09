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
		profileName    string
		mode           apparmorprofileapi.AppArmorMode
		abstract       *apparmorprofileapi.AppArmorAbstract
		mustContain    []string
		mustNotContain []string
		wantErr        bool
	}{
		{
			name:        "Generate profile with enforce mode with deny",
			profileName: "EnforceModeWithDeny",
			mode:        apparmorprofileapi.AppArmorModeEnforce,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/etc/passwd"},
				},
			},
			mustContain: []string{
				"profile EnforceModeWithDeny flags=(enforce",
				"/etc/passwd r,",
				"deny /etc/passwd wlk,",
				"deny @{PROC}/* w,",
			},
			wantErr: false,
		},
		{
			name:        "Generate profile with complain mode without deny",
			profileName: "ComplainModeWithoutDeny",
			mode:        apparmorprofileapi.AppArmorModeComplain,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/etc/passwd"},
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
			wantErr: false,
		},
		{
			name:        "Name sanitization - good - alphanumeric and dashes",
			profileName: "my-app_profile.v1",
			abstract:    &apparmorprofileapi.AppArmorAbstract{},
			wantErr:     false,
		},
		{
			name:        "Name sanitization - good(spoc) -  alphanumerical profile path",
			profileName: "/path/to/my/profile",
			abstract:    &apparmorprofileapi.AppArmorAbstract{},
			wantErr:     false,
		},
		{
			name:        "Name sanitization - bad - contains space",
			profileName: "my profile",
			abstract:    &apparmorprofileapi.AppArmorAbstract{},
			wantErr:     true,
		},
		{
			name:        "Name sanitization - bad - newline injection",
			profileName: "profile\n  audit network inet,",
			abstract:    &apparmorprofileapi.AppArmorAbstract{},
			wantErr:     true,
		},
		{
			name: "Path sanitization - good - standard absolute path",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/usr/bin/nginx"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - good - path with AppArmor variables",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/proc/@{pid}/cgroup", "/@{HOME}/.bashrc"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - good - path with wildcards",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/var/log/**", "/etc/nginx/conf.d/*.conf", "/lib/tls/i686/cmov/lib*.so?"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - good - path with special allowed characters and spaces",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/opt/my-app/v1.2+3/run_app", "/My Documents/test file"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - bad - missing leading slash (relative path)",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"usr/bin/nginx"}, // Fails the ^/ requirement
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - quote injection attempt",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{`/usr/bin/nginx" - r,`}, // Quotes are not in the allowed regex class
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - shell execution injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/usr/bin/$(whoami)"}, // $ and () are not allowed
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - rule breakout with comma",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/usr/bin/nginx, /etc/passwd"}, // Comma is not allowed
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - command chaining",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/usr/bin/nginx ; rm -rf /"}, // Semicolon is not allowed
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - good - standard absolute path",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/usr/bin/nginx"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - good - library with wildcard",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedLibraries: []string{"/lib/x86_64-linux-gnu/**"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - bad - relative path",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"usr/bin/app"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - newline structural injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					// Attempting to break out of the string to start a new rule
					AllowedExecutables: []string{"/var/log/app.log\n  audit network inet,"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - quote injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					// Attempting to close the template's quotes early
					AllowedLibraries: []string{"/var/log/\"app\".log"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - directory traversal",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/usr/bin/../etc/shadow"},
				},
			},
			wantErr: true,
		},
		{
			name: "Capabilities sanitization - good - standard capability",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{"chown"},
				},
			},
			wantErr: false,
		},
		{
			name: "Capabilities sanitization - good - mixed case",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{"DAC_OVERRIDE"},
				},
			},
			wantErr: false,
		},
		{
			name: "Capabilities sanitization - bad - includes CAP_ prefix",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{"CAP_CHOWN"},
				},
			},
			wantErr: true,
		},
		{
			name: "Capabilities sanitization - bad - comma injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{"chown, net_admin"},
				},
			},
			wantErr: true,
		},
		{
			name: "Capabilities sanitization - bad - keyword injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					// 'audit' is an AppArmor keyword, not a valid capability string ('audit_write' is valid)
					AllowedCapabilities: []string{"audit"},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := GenerateProfile(tc.profileName, tc.mode, tc.abstract)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			for _, s := range tc.mustContain {
				require.Contains(t, got, s)
			}

			for _, s := range tc.mustNotContain {
				require.NotContains(t, got, s)
			}
		})
	}
}
