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
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func TestGenerateProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		profileName string
		mode        apparmorprofileapi.AppArmorMode
		abstract    *apparmorprofileapi.AppArmorAbstract
		wantErr     bool
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
			wantErr: false,
		},
		{
			name:        "Capabilities stored in other spellings are normalized",
			profileName: "NormalizedCapabilities",
			mode:        apparmorprofileapi.AppArmorModeEnforce,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{" NET_ADMIN", "Sys_Rawio "},
				},
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
					ReadOnlyPaths: []string{
						"/var/log/**",
						"/etc/nginx/conf.d/*.conf",
						"/lib/tls/i686/cmov/lib*.so?",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - good - path with special allowed characters and spaces",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{
						"/opt/my-app/v1.2+3/run_app",
						"/My Documents/test file",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Path quoting - paths with spaces are quoted",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/opt/my app/bin"},
					AllowedLibraries:   []string{"/opt/my app/lib.so"},
				},
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths:  []string{"/My Documents/test file", "/etc/passwd"},
					WriteOnlyPaths: []string{"/var/log/my app.log"},
					ReadWritePaths: []string{"/tmp/@{pid}/a b/*"},
				},
			},
			wantErr: false,
		},
		{
			name: "Path sanitization - good - only root",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/"},
				},
			},
			wantErr: false,
		},
		{
			name:        "Ptrace field - enforce mode with peer",
			profileName: "PtraceFieldEnforce",
			mode:        apparmorprofileapi.AppArmorModeEnforce,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessTrace,
						apparmorprofileapi.AppArmorPtraceAccessRead,
					},
					Peer: "@{profile_name}",
				},
			},
			wantErr: false,
		},
		{
			name:        "Ptrace field - complain mode without peer",
			profileName: "PtraceFieldComplain",
			mode:        apparmorprofileapi.AppArmorModeComplain,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessReadBy,
						apparmorprofileapi.AppArmorPtraceAccessTracedBy,
					},
				},
			},
			wantErr: false,
		},
		{
			// The deprecated rules in the paths still apply next to the field.
			name:        "Ptrace field - combined with deprecated rules in the paths",
			profileName: "PtraceFieldAndPaths",
			mode:        apparmorprofileapi.AppArmorModeEnforce,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"ptrace (readby),", "/var/run/app.sock"},
				},
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessRead,
						apparmorprofileapi.AppArmorPtraceAccessRead,
					},
					Peer: "cri-containerd.apparmor.d//*",
				},
			},
			wantErr: false,
		},
		{
			name: "Ptrace field - bad - unknown access",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{"everything"},
				},
			},
			wantErr: true,
		},
		{
			name: "Ptrace field - bad - access injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						"read), /etc/shadow r, ptrace (read",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Ptrace field - bad - peer injection",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessRead,
					},
					Peer: "unconfined,\n  /etc/shadow r",
				},
			},
			wantErr: true,
		},
		{
			name: "Ptrace field - bad - peer with unbalanced brace",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessRead,
					},
					Peer: "@{profile_name",
				},
			},
			wantErr: true,
		},
		{
			name: "Ptrace field - bad - peer without access",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{Peer: "unconfined"},
			},
			wantErr: true,
		},
		{
			// Profiles used to put ptrace rules into the paths before the
			// API had a field for them. They must become ptrace rules and
			// never a "deny ptrace" rule, which the enforce mode renders for
			// paths.
			name:        "Ptrace rules in the paths - enforce mode",
			profileName: "PtraceEnforce",
			mode:        apparmorprofileapi.AppArmorModeEnforce,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{
						"ptrace (read),",
						"ptrace (trace), # ugly template injection hack",
						"/etc/passwd",
					},
					WriteOnlyPaths: []string{"ptrace (Read),"},
					ReadWritePaths: []string{
						"ptrace (read),\n# ugly template injection hack",
						"/var/run/app.sock",
					},
				},
			},
			wantErr: false,
		},
		{
			name:        "Ptrace rules in the paths - complain mode",
			profileName: "PtraceComplain",
			mode:        apparmorprofileapi.AppArmorModeComplain,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"ptrace (readby),  # comment"},
				},
			},
			wantErr: false,
		},
		{
			name: "Ptrace rules - bad - unknown access",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"ptrace (everything),"},
				},
			},
			wantErr: true,
		},
		{
			// The API accepts ptrace rules in the executables and libraries
			// as well, which used to fail the validation forever.
			name:        "Ptrace rules in the executables and libraries",
			profileName: "PtraceExecutables",
			mode:        apparmorprofileapi.AppArmorModeEnforce,
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"ptrace (read),", "/usr/bin/app"},
					AllowedLibraries:   []string{"/usr/lib/libapp.so", "ptrace (Trace), # comment"},
				},
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"ptrace (read),", "/etc/passwd"},
				},
			},
			wantErr: false,
		},
		{
			name: "Ptrace rules - bad - unknown access in the executables",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"ptrace (everything),"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - malicious ptrace attempt",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					// Fails because there is no comma, or tries to inject file rules after ptrace
					ReadOnlyPaths: []string{"ptrace (read) /etc/shadow r,"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - empty path",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/etc/passwd", ""},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - empty executable",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{""},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - unbalanced opening brace",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{"/{"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - unbalanced closing brace",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					WriteOnlyPaths: []string{"/a}"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - unbalanced variable",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedLibraries: []string{"/@{"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - empty variable",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedLibraries: []string{"/@{}"},
				},
			},
			wantErr: true,
		},
		{
			// apparmor_parser rejects a brace group without a comma.
			name: "Path sanitization - bad - alternation",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"/a/{b}/c"},
				},
			},
			wantErr: true,
		},
		{
			name: "Path sanitization - bad - nested braces",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"/{a{b}}"},
				},
			},
			wantErr: true,
		},
		{
			// Earlier releases accepted a literal @, for example in the
			// paths of systemd template units.
			name: "Path sanitization - good - literal at",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths: []string{
						"/sys/fs/cgroup/system.slice/foo@1.service",
						"/a@b",
						"/home/@{HOME}/.config@",
					},
				},
			},
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
					ReadOnlyPaths: []string{
						`/usr/bin/nginx" - r,`,
					}, // Quotes are not in the allowed regex class
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
					ReadOnlyPaths: []string{
						"/usr/bin/nginx ; rm -rf /",
					}, // Semicolon is not allowed
				},
			},
			wantErr: true,
		},
		{
			name: "Executable sanitization - good - standard absolute path",
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

				return
			}

			require.NoError(t, err)
			utiltest.Golden(t, goldenName(tc.name), []byte(got))
		})
	}
}

// goldenName turns a test case name into the name of its golden file.
func goldenName(name string) string {
	return strings.Trim(nonAlphanumeric.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)

// A ptrace rule put into the paths used to be rendered like a path, which the
// enforce mode turned into a "deny ptrace" rule overriding the allow.
func TestGenerateProfilePtraceIsNeverDenied(t *testing.T) {
	t.Parallel()

	got, err := GenerateProfile("ptrace", apparmorprofileapi.AppArmorModeEnforce,
		&apparmorprofileapi.AppArmorAbstract{
			Filesystem: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"ptrace (trace), # comment"},
				ReadWritePaths: []string{"ptrace (read),"},
			},
		})
	require.NoError(t, err)
	require.Contains(t, got, "\n  ptrace (read),\n  ptrace (trace),\n")
	require.NotContains(t, got, "deny ptrace")
	require.NotContains(t, got, "# comment")
	require.NotContains(t, got, "), r,")
	require.NotContains(t, got, "), rwlk,")
}

func TestUsesDeprecatedPtraceRules(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		abstract *apparmorprofileapi.AppArmorAbstract
		want     bool
	}{
		{name: "nil", abstract: nil},
		{name: "no filesystem", abstract: &apparmorprofileapi.AppArmorAbstract{}},
		{
			name: "only paths",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{ReadOnlyPaths: []string{"/etc/passwd"}},
			},
		},
		{
			name: "ptrace field",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessRead,
					},
				},
			},
		},
		{
			name: "rule in write only paths",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{WriteOnlyPaths: []string{"ptrace (read),"}},
			},
			want: true,
		},
		{
			name: "rule in allowed executables",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/usr/bin/app", "ptrace (read),"},
				},
			},
			want: true,
		},
		{
			name: "rule in allowed libraries",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedLibraries: []string{"ptrace (trace), # comment"},
				},
			},
			want: true,
		},
		{
			name: "only executables",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"/usr/bin/app"},
				},
			},
		},
		{
			name: "rule with comment in read write paths",
			abstract: &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"/tmp", "ptrace (read),\n# ugly template injection hack"},
				},
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, UsesDeprecatedPtraceRules(tc.abstract))
		})
	}
}
