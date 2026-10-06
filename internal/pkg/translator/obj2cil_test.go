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

package translator

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func TestObject2CIL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		profile     *selinuxprofileapi.SelinuxProfile
		options     *Options
		want        string
		inheritsys  []string
		inheritobjs []selinuxprofileapi.SelinuxProfileObject
		wantErr     bool
	}{
		{
			name: "Test errorlogger translation with system inheritance",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
								"read",
								"getattr",
								"lock",
								"search",
								"ioctl",
								"add_name",
								"remove_name",
								"write",
							},
							"file": []string{
								"getattr",
								"read",
								"write",
								"append",
								"ioctl",
								"lock",
								"map",
								"open",
								"create",
							},
							"sock_file": []string{
								"getattr",
								"read",
								"write",
								"append",
								"open",
							},
						},
					},
				},
			},
			want: "(block foo-bar\n" +
				"(blockinherit container)\n" +
				"(allow process var_log_t ( dir ( add_name getattr ioctl lock open read remove_name search write )))\n" +
				"(allow process var_log_t ( file ( append create getattr ioctl lock map open read write )))\n" +
				"(allow process var_log_t ( sock_file ( append getattr open read write )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with @self",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-selinux-recording-nginx",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Kind: selinuxprofileapi.SystemPolicyKind,
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"http_port_t": {
							"tcp_socket": []string{
								"name_bind",
							},
						},
						"node_t": {
							"tcp_socket": []string{
								"name_bind",
							},
						},
						"proc_t": {
							"filesystem": []string{
								"associate",
							},
						},
						"@self": {
							"tcp_socket": []string{
								"listen",
							},
						},
					},
				},
			},
			want: "(block test-selinux-recording-nginx\n" +
				"(blockinherit container)\n" +
				"(allow process test-selinux-recording-nginx.process ( tcp_socket ( listen )))\n" +
				"(allow process http_port_t ( tcp_socket ( name_bind )))\n" +
				"(allow process node_t ( tcp_socket ( name_bind )))\n" +
				"(allow process proc_t ( filesystem ( associate )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test successful inherit reference",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-selinux-recording-nginx",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Kind: "SelinuxPolicy",
							Name: "foo",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"http_port_t": {
							"tcp_socket": []string{
								"name_bind",
							},
						},
					},
				},
			},
			want: "(block test-selinux-recording-nginx\n" +
				"(blockinherit foo)\n" +
				"(allow process http_port_t ( tcp_socket ( name_bind )))\n" +
				")\n",
			inheritobjs: []selinuxprofileapi.SelinuxProfileObject{
				&selinuxprofileapi.SelinuxProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
		},
		{
			name: "Test errorlogger translation with permissive mode",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-permissive-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Mode: selinuxprofileapi.SelinuxModePermissive,
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
								"read",
								"getattr",
								"lock",
								"search",
								"ioctl",
								"add_name",
								"remove_name",
								"write",
							},
							"file": []string{
								"getattr",
								"read",
								"write",
								"append",
								"ioctl",
								"lock",
								"map",
								"open",
								"create",
							},
							"sock_file": []string{
								"getattr",
								"read",
								"write",
								"append",
								"open",
							},
						},
					},
				},
			},
			want: "(block foo-permissive-bar\n" +
				"(blockinherit container)\n" +
				"(typepermissive process)\n" +
				"(allow process var_log_t ( dir ( add_name getattr ioctl lock open read remove_name search write )))\n" +
				"(allow process var_log_t ( file ( append create getattr ioctl lock map open read write )))\n" +
				"(allow process var_log_t ( sock_file ( append getattr open read write )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test errorlogger translation with explicit enforcing mode",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-enforcing-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Mode: selinuxprofileapi.SelinuxModeEnforcing,
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
							},
						},
					},
				},
			},
			want: "(block foo-enforcing-bar\n" +
				"(blockinherit container)\n" +
				"(allow process var_log_t ( dir ( open )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with another template than container",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "net_container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
							},
							"file": []string{
								"getattr",
							},
							"sock_file": []string{
								"getattr",
							},
						},
					},
				},
			},
			want: "(block foo-bar\n" +
				"(blockinherit container)\n" +
				"(blockinherit net_container)\n" +
				"(allow process var_log_t ( dir ( open )))\n" +
				"(allow process var_log_t ( file ( getattr )))\n" +
				"(allow process var_log_t ( sock_file ( getattr )))\n" +
				")\n",
			inheritsys: []string{
				"container",
				"net_container",
			},
		},
		{
			name: "Test translation with forbidden type",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"kernel_t": {
							"dir": []string{
								"open",
							},
						},
					},
				},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with forbidden class",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"security": []string{
								"open",
							},
						},
					},
				},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with forbidden permission",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"load_policy",
							},
						},
					},
				},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation without denied options",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
							},
						},
					},
				},
			},
			want: "(block foo-bar\n" +
				"(blockinherit container)\n" +
				"(allow process var_log_t ( dir ( open )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with denied type",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
							},
						},
					},
				},
			},
			options: &Options{
				DeniedTypes: []string{"var_log_t"},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with denied class",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
							},
						},
					},
				},
			},
			options: &Options{
				DeniedClasses: []string{"dir"},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with denied permission",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"dir": []string{
								"open",
							},
						},
					},
				},
			},
			options: &Options{
				DeniedPermissions: []string{"open"},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation allowing a built-in denied type",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"kernel_t": {
							"file": []string{
								"open",
							},
						},
					},
				},
			},
			options: &Options{
				AllowedTypes: []string{"kernel_t"},
			},
			want: "(block foo-bar\n" +
				"(blockinherit container)\n" +
				"(allow process kernel_t ( file ( open )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation allowing a built-in denied class",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"capability": []string{
								"net_admin",
							},
						},
					},
				},
			},
			options: &Options{
				AllowedClasses: []string{"capability"},
			},
			want: "(block foo-bar\n" +
				"(blockinherit container)\n" +
				"(allow process var_log_t ( capability ( net_admin )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation allowing a built-in denied permission",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"file": []string{
								"mounton",
							},
						},
					},
				},
			},
			options: &Options{
				AllowedPermissions: []string{"mounton"},
			},
			want: "(block foo-bar\n" +
				"(blockinherit container)\n" +
				"(allow process var_log_t ( file ( mounton )))\n" +
				")\n",
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation with a type both denied (higher precedence) and allowed",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selinuxprofileapi.Allow{
						"kernel_t": {
							"file": []string{
								"open",
							},
						},
					},
				},
			},
			// A user-specified deny takes precedence over an allow for the same
			// entry, so translation is rejected.
			options: &Options{
				DeniedTypes:  []string{"kernel_t"},
				AllowedTypes: []string{"kernel_t"},
			},
			wantErr: true,
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test translation sorts the labels, object classes and permissions",
			profile: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bar",
				},
				Spec: selinuxprofileapi.SelinuxProfileSpec{
					Mode: selinuxprofileapi.SelinuxModePermissive,
					Inherit: []selinuxprofileapi.PolicyRef{
						{
							Name: "container",
						},
						{
							Name: "net_container",
						},
						{
							Kind: selinuxprofileapi.SelinuxProfilePolicyKind,
							Name: "foo",
						},
					},
					// The labels, object classes and permissions are unsorted.
					Allow: selinuxprofileapi.Allow{
						"var_log_t": {
							"sock_file": {"write", "open"},
							"dir":       {"search", "open"},
							"file":      {"read", "open", "read"},
						},
						"proc_t": {
							"filesystem": {"associate"},
						},
						selinuxprofileapi.AllowSelf: {
							"tcp_socket": {"listen"},
						},
						"http_port_t": {
							"udp_socket": {"name_bind"},
							"tcp_socket": {"name_bind"},
						},
					},
				},
			},
			// The inherited profile already inherits the container template.
			want: "(block foo-bar\n" +
				"(blockinherit net_container)\n" +
				"(blockinherit foo)\n" +
				"(typepermissive process)\n" +
				"(allow process foo-bar.process ( tcp_socket ( listen )))\n" +
				"(allow process http_port_t ( tcp_socket ( name_bind )))\n" +
				"(allow process http_port_t ( udp_socket ( name_bind )))\n" +
				"(allow process proc_t ( filesystem ( associate )))\n" +
				"(allow process var_log_t ( dir ( open search )))\n" +
				"(allow process var_log_t ( file ( open read )))\n" +
				"(allow process var_log_t ( sock_file ( open write )))\n" +
				")\n",
			inheritsys: []string{
				"container",
				"net_container",
			},
			inheritobjs: []selinuxprofileapi.SelinuxProfileObject{
				&selinuxprofileapi.SelinuxProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Object2CIL(tt.inheritsys, tt.inheritobjs, tt.profile, tt.options)
			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestObject2CILRejectsInvalidIdentifiers(t *testing.T) {
	t.Parallel()

	profile := func(name string, allow selinuxprofileapi.Allow) *selinuxprofileapi.SelinuxProfile {
		return &selinuxprofileapi.SelinuxProfile{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       selinuxprofileapi.SelinuxProfileSpec{Allow: allow},
		}
	}

	valid := selinuxprofileapi.Allow{"var_log_t": {"file": {"read"}}}

	for _, tc := range []struct {
		name           string
		profile        *selinuxprofileapi.SelinuxProfile
		systemInherits []string
		objInherits    []selinuxprofileapi.SelinuxProfileObject
	}{
		{
			name: "class key injecting an allow rule",
			profile: profile("foo", selinuxprofileapi.Allow{
				"var_log_t": {
					"file ( read ))) (allow process shadow_t (file": {"read"},
				},
			}),
		},
		{
			name: "class key with whitespace bypassing the denylist",
			profile: profile("foo", selinuxprofileapi.Allow{
				"var_log_t": {" security": {"setenforce"}},
			}),
		},
		{
			name: "class key with a trailing newline",
			profile: profile("foo", selinuxprofileapi.Allow{
				"var_log_t": {"security\n": {"load_policy"}},
			}),
		},
		{
			name: "type key with parentheses",
			profile: profile("foo", selinuxprofileapi.Allow{
				"var_log_t (file (read))) (allow process shadow_t": {"file": {"read"}},
			}),
		},
		{
			name: "permission with parentheses",
			profile: profile("foo", selinuxprofileapi.Allow{
				"var_log_t": {"file": {"read ))) (allow process shadow_t (file (read"}},
			}),
		},
		{
			name:    "profile name with a dot",
			profile: profile("foo.bar", valid),
		},
		{
			name:    "profile name starting with a digit",
			profile: profile("1foo", valid),
		},
		{
			name:           "system inherit with parentheses",
			profile:        profile("foo", valid),
			systemInherits: []string{"container) (allow process shadow_t (file (read)))"},
		},
		{
			name:    "object inherit with whitespace",
			profile: profile("foo", valid),
			objInherits: []selinuxprofileapi.SelinuxProfileObject{
				profile("bar baz", valid),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Object2CIL(tc.systemInherits, tc.objInherits, tc.profile, nil)
			require.ErrorIs(t, err, errInvalidIdentifier)
			require.Empty(t, got)
		})
	}
}

func TestObject2CILAllowsValidIdentifiers(t *testing.T) {
	t.Parallel()

	sp := &selinuxprofileapi.SelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "foo-bar_1"},
		Spec: selinuxprofileapi.SelinuxProfileSpec{
			Allow: selinuxprofileapi.Allow{
				selinuxprofileapi.AllowSelf: {"tcp_socket": {"listen"}},
				"other.process":             {"unix_stream_socket": {"connectto"}},
			},
		},
	}

	got, err := Object2CIL([]string{"container", "net_container"}, nil, sp, nil)
	require.NoError(t, err)
	require.Contains(t, got, "(block foo-bar_1\n")
	require.Contains(t, got, "(blockinherit net_container)\n")
	require.Contains(t, got, "(allow process foo-bar_1.process ( tcp_socket ( listen )))\n")
	require.Contains(t, got, "(allow process other.process ( unix_stream_socket ( connectto )))\n")
}
