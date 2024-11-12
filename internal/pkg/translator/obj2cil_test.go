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

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

func TestObject2CIL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		profile     *selxv1alpha2.SelinuxProfile
		wantMatches []string
		doNotMatch  []string
		inheritsys  []string
		inheritobjs []selxv1alpha2.SelinuxProfileObject
	}{
		{
			name: "Test errorlogger translation with system inheritance",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selxv1alpha2.Allow{
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
				"\\(block foo_bar",
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
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-selinux-recording-nginx",
					Namespace: "default",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Kind: selxv1alpha2.SystemPolicyKind,
							Name: "container",
						},
					},
					Allow: selxv1alpha2.Allow{
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
				"\\(block test-selinux-recording-nginx_default",
				"\\(blockinherit container\\)",
				// We match on several lines since we don't care about the order
				"\\(allow process http_port_t \\( tcp_socket \\(.*name_bind.*\\)\\)\\)\n",
				"\\(allow process node_t \\( tcp_socket \\(.*name_bind.*\\)\\)\\)\n",
				"\\(allow process proc_t \\( filesystem \\(.*associate.*\\)\\)\\)\n",
				"\\(allow process test-selinux-recording-nginx_default.process \\( tcp_socket " +
					"\\(.*listen.*\\)\\)\\)\n",
			},
			inheritsys: []string{
				"container",
			},
		},
		{
			name: "Test successful inherit reference",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-selinux-recording-nginx",
					Namespace: "default",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Kind: "SelinuxPolicy",
							Name: "foo",
						},
					},
					Allow: selxv1alpha2.Allow{
						"http_port_t": {
							"tcp_socket": []string{
								"name_bind",
							},
						},
					},
				},
			},
			wantMatches: []string{
				"\\(block test-selinux-recording-nginx_default",
				"\\(blockinherit foo_default\\)",
				"\\(allow process http_port_t \\( tcp_socket \\(.*name_bind.*\\)\\)\\)\\n",
			},
			doNotMatch: []string{
				"\\(blockinherit container\\)",
			},
			inheritobjs: []selxv1alpha2.SelinuxProfileObject{
				&selxv1alpha2.SelinuxProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "Test errorlogger translation with permissive mode",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo-permissive",
					Namespace: "bar",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Permissive: true,
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Name: "container",
						},
					},
					Allow: selxv1alpha2.Allow{
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
				"\\(block foo-permissive_bar",
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
			name: "Test translation with another template than container",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Name: "net_container",
						},
					},
					Allow: selxv1alpha2.Allow{
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
				"\\(block foo_bar",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Object2CIL(tt.inheritsys, tt.inheritobjs, tt.profile)
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
