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

package translator

import (
	"regexp"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func TestObject2CIL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		profile     *selinuxprofileapi.SelinuxProfile
		wantMatches []string
		doNotMatch  []string
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
			wantMatches: []string{
				"\\(block foo-bar",
				"\\(blockinherit container\\)",
				// We match on several lines since we don't care about the order
				"\\(allow process var_log_t \\( dir \\(.*open.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( dir \\(.*read.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( dir \\(.*remove_name.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( dir \\(.*write.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*getattr.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*map.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*create.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*getattr.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*append.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*open.*\\)\\)\\)\n",
			},
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
			wantMatches: []string{
				"\\(block test-selinux-recording-nginx",
				"\\(blockinherit container\\)",
				// We match on several lines since we don't care about the order
				"\\(allow process http_port_t \\( tcp_socket \\(.*name_bind.*\\)\\)\\)\n",
				"\\(allow process node_t \\( tcp_socket \\(.*name_bind.*\\)\\)\\)\n",
				"\\(allow process proc_t \\( filesystem \\(.*associate.*\\)\\)\\)\n",
				"\\(allow process test-selinux-recording-nginx.process \\( tcp_socket " +
					"\\(.*listen.*\\)\\)\\)\n",
			},
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
			wantMatches: []string{
				"\\(block test-selinux-recording-nginx",
				"\\(blockinherit foo\\)",
				"\\(allow process http_port_t \\( tcp_socket \\(.*name_bind.*\\)\\)\\)\\n",
			},
			doNotMatch: []string{
				"\\(blockinherit container\\)",
			},
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
			wantMatches: []string{
				"\\(block foo-permissive-bar",
				"\\(blockinherit container\\)",
				"\\(typepermissive process\\)",
				// We match on several lines since we don't care about the order
				"\\(allow process var_log_t \\( dir \\(.*open.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( dir \\(.*read.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( dir \\(.*remove_name.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( dir \\(.*write.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*getattr.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*map.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*create.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*getattr.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*append.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*open.*\\)\\)\\)\n",
			},
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
			wantMatches: []string{
				"\\(block foo-enforcing-bar",
				"\\(blockinherit container\\)",
				"\\(allow process var_log_t \\( dir \\(.*open.*\\)\\)\\)\n",
			},
			doNotMatch: []string{
				"\\(typepermissive process\\)",
			},
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
			wantMatches: []string{
				"\\(block foo-bar",
				"\\(blockinherit container\\)",
				"\\(blockinherit net_container\\)",
				// We match on several lines since we don't care about the order
				"\\(allow process var_log_t \\( dir \\(.*open.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( file \\(.*getattr.*\\)\\)\\)\n",
				"\\(allow process var_log_t \\( sock_file \\(.*getattr.*\\)\\)\\)\n",
			},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Object2CIL(tt.inheritsys, tt.inheritobjs, tt.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("Object2CIL() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			for _, wantMatch := range tt.wantMatches {
				matched, err := regexp.MatchString(wantMatch, got)
				if err != nil {
					t.Errorf("Error matching parsed CIL to expected result: %s", err)
				} else if !matched {
					t.Errorf("The generated CIL didn't match expectation.\nExpected match for: %s\nGenerated CIL: %s", wantMatch, got)
				}
			}

			for _, doNotMatch := range tt.doNotMatch {
				matched, err := regexp.MatchString(doNotMatch, got)
				if err != nil {
					t.Errorf("Error matching parsed CIL to expected result: %s", err)
				} else if matched {
					t.Errorf("The generated CIL matched expectation.\nExpected no match for: %s\nGenerated CIL: %s", doNotMatch, got)
				}
			}
		})
	}
}
