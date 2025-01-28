/*
Copyright 2020 The Kubernetes Authors.

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

package selinuxprofile

import (
	"context"
	"os"
	"regexp"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func Test_selinuxProfileHandler(t *testing.T) {
	t.Parallel()

	ns := "security-profiles-operator"
	//nolint:tenv // we want to set the env here
	os.Setenv("OPERATOR_NAMESPACE", ns)

	schemeInstance := scheme.Scheme
	if err := spodv1alpha1.AddToScheme(schemeInstance); err != nil {
		t.Fatalf("couldn't add SPOD API to scheme")
	}

	if err := selxv1alpha2.AddToScheme(schemeInstance); err != nil {
		t.Fatalf("couldn't add SPOD API to scheme")
	}

	spodinstance := bindata.DefaultSPOD.DeepCopy()
	spodinstance.Namespace = ns

	tests := []struct {
		name            string
		profile         selxv1alpha2.SelinuxProfileObject
		wantInitErr     bool
		wantValidateErr bool
		wantErrMatches  []string
		existingObjs    []client.Object
		missingProfile  bool
	}{
		{
			name: "Test validate errorlogger with default Kind",
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
						"@self": {
							"tcp_socket": []string{
								"listen",
							},
						},
					},
				},
			},
			existingObjs: []client.Object{
				spodinstance.DeepCopy(),
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
							Kind: "SelinuxProfile",
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
			existingObjs: []client.Object{
				spodinstance.DeepCopy(),
				&selxv1alpha2.SelinuxProfile{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "default",
					},
				},
			},
		},
		{
			name: "Test unexistent system reference",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-selinux-recording-nginx",
					Namespace: "default",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Kind: selxv1alpha2.SystemPolicyKind,
							Name: "unexistent-system-ref",
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
			wantValidateErr: true,
			wantErrMatches: []string{
				"system profile unexistent-system-ref not in SecurityProfilesOperatorDaemon's allow list",
			},
			existingObjs: []client.Object{
				spodinstance.DeepCopy(),
			},
		},
		{
			name: "Test unexistent inherit reference",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-selinux-recording-nginx",
					Namespace: "default",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Kind: "SelinuxProfile",
							Name: "unexistent-ref",
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
			wantValidateErr: true,
			wantErrMatches: []string{
				"couldn't find inherit reference SelinuxProfile/unexistent-ref",
			},
			existingObjs: []client.Object{
				spodinstance.DeepCopy(),
			},
		},
		{
			name: "Test invalid kind in inherit reference",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-selinux-recording-nginx",
					Namespace: "default",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Kind: "InvalidKind",
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
			wantValidateErr: true,
			wantErrMatches: []string{
				"InvalidKind/foo: unknown inherit kind for entry",
			},
			existingObjs: []client.Object{
				spodinstance.DeepCopy(),
			},
		},
		{
			name: "Test missing profile",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-selinux-recording-nginx",
					Namespace: "default",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Inherit: []selxv1alpha2.PolicyRef{
						{
							Kind: "SelinuxProfile",
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
			missingProfile: true,
			wantInitErr:    true,
			wantErrMatches: []string{
				"\"test-selinux-recording-nginx\" not found",
			},
		},
		{
			name: "Test validate injection through label key",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Allow: selxv1alpha2.Allow{
						"var_log_t) (typeattribute container_runtime_domain (process))": {
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
						},
					},
				},
			},
			wantValidateErr: true,
			wantErrMatches: []string{
				"didn't match expected characters: invalid label key",
			},
		},
		{
			name: "Test validate injection through object class key",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
					Allow: selxv1alpha2.Allow{
						"var_log_t": {
							"dir) (typeattribute container_runtime_domain (process))": []string{
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
						},
					},
				},
			},
			wantValidateErr: true,
			wantErrMatches: []string{
				"didn't match expected characters: invalid object class",
			},
		},
		{
			name: "Test validate injection through object permission",
			profile: &selxv1alpha2.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo",
					Namespace: "bar",
				},
				Spec: selxv1alpha2.SelinuxProfileSpec{
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
								"write) (typeattribute container_runtime_domain (process))",
							},
						},
					},
				},
			},
			wantValidateErr: true,
			wantErrMatches: []string{
				"didn't match expected characters: invalid permission",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !tt.missingProfile {
				tt.existingObjs = append(tt.existingObjs, tt.profile)
			}

			cli := fake.NewClientBuilder().WithScheme(schemeInstance).WithObjects(tt.existingObjs...).Build()
			key := types.NamespacedName{Name: tt.profile.GetName(), Namespace: tt.profile.GetNamespace()}
			sph, initerr := newSelinuxProfileHandler(context.TODO(), cli, key)

			if (initerr != nil) != tt.wantInitErr {
				t.Errorf("newSelinuxProfileHandler() error = %v, wantErr %v", initerr, tt.wantInitErr)
			}
			// There was an expected error
			if (initerr != nil) && tt.wantInitErr {
				for _, wantMatch := range tt.wantErrMatches {
					matched, matcherr := regexp.MatchString(wantMatch, initerr.Error())
					if matcherr != nil {
						t.Errorf("failed matching the error to expected string: %s", matcherr)
					} else if !matched {
						t.Errorf("The error didn't match expectation.\nExpected match for: %s\nGot instead: %s", wantMatch, initerr)
					}
				}

				return
			}

			valerr := sph.Validate()
			if (valerr != nil) != tt.wantValidateErr {
				t.Errorf("selinuxProfileHandler.Validate() error = %v, wantErr %v", valerr, tt.wantValidateErr)
			}
			// there's an expected error
			if (valerr != nil) && tt.wantValidateErr {
				for _, wantMatch := range tt.wantErrMatches {
					matched, matcherr := regexp.MatchString(wantMatch, valerr.Error())
					if matcherr != nil {
						t.Errorf("failed matching the error to expected string: %s", matcherr)
					} else if !matched {
						t.Errorf("The error didn't match expectation.\nExpected match for: %s\nGot instead: %s", wantMatch, valerr)
					}
				}
			}
		})
	}
}
