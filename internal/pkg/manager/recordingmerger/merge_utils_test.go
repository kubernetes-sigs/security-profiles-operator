/*
Copyright 2022 The Kubernetes Authors.

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

package recordingmerger

import (
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func ifaceAsSortedSeccompProfile(iface client.Object) *seccompprofile.SeccompProfile {
	prof, ok := iface.(*seccompprofile.SeccompProfile)
	if !ok {
		return nil
	}

	for i := range prof.Spec.Syscalls {
		sort.Strings(prof.Spec.Syscalls[i].Names)
	}

	sort.Slice(prof.Spec.Syscalls, func(i, j int) bool {
		return prof.Spec.Syscalls[i].Action < prof.Spec.Syscalls[j].Action
	})

	return prof
}

func ifaceAsSortedSelinuxProfile(iface client.Object) *selinuxprofileapi.SelinuxProfile {
	prof, ok := iface.(*selinuxprofileapi.SelinuxProfile)
	if !ok {
		return nil
	}

	for label, permMap := range prof.Spec.Allow {
		for oc, perms := range permMap {
			sort.Strings(perms)
			prof.Spec.Allow[label][oc] = perms
		}
	}

	return prof
}

func TestMergeProfiles(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T) []client.Object
		assert  func(profile client.Object) error
	}{
		{
			name: "Two seccomp profiles",
			prepare: func(t *testing.T) []client.Object {
				t.Helper()

				return []client.Object{
					&seccompprofile.SeccompProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-abc",
						},
						Spec: seccompprofile.SeccompProfileSpec{
							BaseProfileName: "part1",
							DefaultAction:   seccompprofile.ActAllow,
							Syscalls: []seccompprofile.Syscall{
								{
									Names:  []string{"a", "b", "c"},
									Action: seccompprofile.ActErrno,
								},
							},
						},
					},
					&seccompprofile.SeccompProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-ced",
						},
						Spec: seccompprofile.SeccompProfileSpec{
							BaseProfileName: "part1",
							DefaultAction:   seccompprofile.ActAllow,
							Syscalls: []seccompprofile.Syscall{
								{
									Names:  []string{"c", "e", "d"},
									Action: seccompprofile.ActErrno,
								},
							},
						},
					},
				}
			},
			assert: func(mergedProfIface client.Object) error {
				t.Helper()

				mergedProf := ifaceAsSortedSeccompProfile(mergedProfIface)
				require.Len(t, mergedProf.Spec.Syscalls, 5)

				for _, sc := range mergedProf.Spec.Syscalls {
					require.Equal(t, seccompprofile.ActErrno, sc.Action)
					require.Len(t, sc.Names, 1)
				}

				allNames := make([]string, 0, 5)

				for _, sc := range mergedProf.Spec.Syscalls {
					allNames = append(allNames, sc.Names[0])
				}

				require.ElementsMatch(t, []string{"a", "b", "c", "d", "e"}, allNames)

				return nil
			},
		},
		{
			name: "Two selinux profiles",
			prepare: func(t *testing.T) []client.Object {
				t.Helper()

				return []client.Object{
					&selinuxprofileapi.SelinuxProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-foobarbaz1",
						},
						Spec: selinuxprofileapi.SelinuxProfileSpec{
							Inherit: []selinuxprofileapi.PolicyRef{
								{
									Kind: "System",
									Name: "container",
								},
							},
							Allow: selinuxprofileapi.Allow{
								"label_foo": {"oc_bar": {"do_bar"}, "oc_baz": {"do_baz"}},
							},
						},
					},
					&selinuxprofileapi.SelinuxProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-foobarbaz2",
						},
						Spec: selinuxprofileapi.SelinuxProfileSpec{
							Inherit: []selinuxprofileapi.PolicyRef{
								{
									Kind: "System",
									Name: "container",
								},
							},
							Allow: selinuxprofileapi.Allow{
								"label_foo": {"oc_bar": {"do_bar"}, "oc_bar2": {"do_bar2"}, "oc_baz2": {"do_baz2"}},
								"label_aaa": {"oc_aaa": {"do_aaa"}, "oc_bbb": {"do_bbb"}},
							},
						},
					},
				}
			},
			assert: func(profile client.Object) error {
				t.Helper()

				mergedProf := ifaceAsSortedSelinuxProfile(profile)
				require.Equal(t, selinuxprofileapi.Allow{
					"label_foo": {"oc_baz": {"do_baz"}, "oc_bar": {"do_bar"}, "oc_bar2": {"do_bar2"}, "oc_baz2": {"do_baz2"}},
					"label_aaa": {"oc_aaa": {"do_aaa"}, "oc_bbb": {"do_bbb"}},
				}, mergedProf.Spec.Allow)

				return nil
			},
		},
		{
			name: "Two apparmor profiles",
			prepare: func(t *testing.T) []client.Object {
				t.Helper()

				return []client.Object{
					&apparmorprofileapi.AppArmorProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-foobarbaz1",
						},
						Spec: apparmorprofileapi.AppArmorProfileSpec{
							Abstract: apparmorprofileapi.AppArmorAbstract{
								Executable: &apparmorprofileapi.AppArmorExecutablesRules{
									AllowedExecutables: []string{"execA", "execB"},
									AllowedLibraries:   []string{"libA"},
								},
								Filesystem: &apparmorprofileapi.AppArmorFsRules{
									ReadOnlyPaths:  []string{"read1", "merged-rw1"},
									WriteOnlyPaths: []string{"write1", "merged-rw2"},
									ReadWritePaths: []string{"readwrite1"},
								},
								Network: &apparmorprofileapi.AppArmorNetworkRules{
									AllowRaw: func() *bool {
										b := true

										return &b
									}(),
								},
								Capability: &apparmorprofileapi.AppArmorCapabilityRules{
									AllowedCapabilities: []string{"sys_admin", "net_admin"},
								},
							},
						},
					},
					&apparmorprofileapi.AppArmorProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-foobarbaz2",
						},
						Spec: apparmorprofileapi.AppArmorProfileSpec{
							Abstract: apparmorprofileapi.AppArmorAbstract{
								Executable: &apparmorprofileapi.AppArmorExecutablesRules{
									AllowedExecutables: []string{"execA", "execC"},
								},
								Filesystem: &apparmorprofileapi.AppArmorFsRules{
									WriteOnlyPaths: []string{"merged-rw1"},
									ReadWritePaths: []string{"merged-rw2"},
								},
								Network: &apparmorprofileapi.AppArmorNetworkRules{
									AllowRaw: func() *bool {
										b := false

										return &b
									}(),
									Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{
										AllowTCP: func() *bool {
											b := true

											return &b
										}(),
									},
								},
								Capability: &apparmorprofileapi.AppArmorCapabilityRules{
									AllowedCapabilities: []string{"net_admin", "net_raw"},
								},
							},
						},
					},
				}
			},
			assert: func(profile client.Object) error {
				t.Helper()

				prof, ok := profile.(*apparmorprofileapi.AppArmorProfile)
				require.True(t, ok)

				require.Equal(t, apparmorprofileapi.AppArmorAbstract{
					Executable: &apparmorprofileapi.AppArmorExecutablesRules{
						AllowedExecutables: []string{"execA", "execB", "execC"},
						AllowedLibraries:   []string{"libA"},
					},
					Filesystem: &apparmorprofileapi.AppArmorFsRules{
						ReadOnlyPaths:  []string{"read1"},
						WriteOnlyPaths: []string{"write1"},
						ReadWritePaths: []string{"merged-rw1", "merged-rw2", "readwrite1"},
					},
					Network: &apparmorprofileapi.AppArmorNetworkRules{
						AllowRaw: func() *bool {
							b := true

							return &b
						}(),
						Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{
							AllowTCP: func() *bool {
								b := true

								return &b
							}(),
						},
					},
					Capability: &apparmorprofileapi.AppArmorCapabilityRules{
						AllowedCapabilities: []string{"net_admin", "net_raw", "sys_admin"},
					},
				}, prof.Spec.Abstract)

				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			partialProfiles := tc.prepare(t)
			mergedProfIface, err := MergeProfiles(partialProfiles)
			require.NoError(t, err)
			err = tc.assert(mergedProfIface)
			require.NoError(t, err)
		})
	}
}

func TestNormalizeSeccompProfile(t *testing.T) {
	t.Parallel()

	profile := &seccompprofile.SeccompProfile{
		Spec: seccompprofile.SeccompProfileSpec{
			DefaultAction: seccompprofile.ActErrno,
			Syscalls: []seccompprofile.Syscall{
				{
					Names:  []string{"write", "read"},
					Action: seccompprofile.ActAllow,
				},
			},
		},
	}

	require.NoError(t, NormalizeProfile(profile))
	require.Len(t, profile.Spec.Syscalls, 2)

	for _, sc := range profile.Spec.Syscalls {
		require.Len(t, sc.Names, 1)
	}

	require.Equal(t, "read", profile.Spec.Syscalls[0].Names[0])
	require.Equal(t, "write", profile.Spec.Syscalls[1].Names[0])
}

func TestNormalizeAppArmorProfile(t *testing.T) {
	t.Parallel()

	profile := &apparmorprofileapi.AppArmorProfile{
		Spec: apparmorprofileapi.AppArmorProfileSpec{
			Abstract: apparmorprofileapi.AppArmorAbstract{
				Executable: &apparmorprofileapi.AppArmorExecutablesRules{
					AllowedExecutables: []string{"z-exec", "a-exec"},
					AllowedLibraries:   []string{"z-lib", "a-lib"},
				},
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadOnlyPaths:  []string{"/z", "/a"},
					WriteOnlyPaths: []string{"/z", "/a"},
					ReadWritePaths: []string{"/z", "/a"},
				},
				Capability: &apparmorprofileapi.AppArmorCapabilityRules{
					AllowedCapabilities: []string{"sys_admin", "chown"},
				},
			},
		},
	}

	require.NoError(t, NormalizeProfile(profile))

	a := profile.Spec.Abstract
	require.Equal(t, []string{"a-exec", "z-exec"}, a.Executable.AllowedExecutables)
	require.Equal(t, []string{"a-lib", "z-lib"}, a.Executable.AllowedLibraries)
	require.Equal(t, []string{"/a", "/z"}, a.Filesystem.ReadOnlyPaths)
	require.Equal(t, []string{"/a", "/z"}, a.Filesystem.WriteOnlyPaths)
	require.Equal(t, []string{"/a", "/z"}, a.Filesystem.ReadWritePaths)
	require.Equal(t, []string{"chown", "sys_admin"}, a.Capability.AllowedCapabilities)
}

func TestNormalizeCheckIdempotent(t *testing.T) {
	t.Parallel()

	profile := &seccompprofile.SeccompProfile{
		Spec: seccompprofile.SeccompProfileSpec{
			DefaultAction: seccompprofile.ActErrno,
			Syscalls: []seccompprofile.Syscall{
				{Names: []string{"read"}, Action: seccompprofile.ActAllow},
				{Names: []string{"write"}, Action: seccompprofile.ActAllow},
			},
		},
	}

	require.NoError(t, NormalizeProfile(profile))

	base := profile.DeepCopy()

	require.NoError(t, NormalizeProfile(profile))
	require.True(t, reflect.DeepEqual(base, profile))
}

func TestNormalizeCheckMergeComparison(t *testing.T) {
	t.Parallel()

	profiles := []client.Object{
		&seccompprofile.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{Name: "base"},
			Spec: seccompprofile.SeccompProfileSpec{
				DefaultAction: seccompprofile.ActErrno,
				Syscalls: []seccompprofile.Syscall{
					{Names: []string{"read", "write"}, Action: seccompprofile.ActAllow},
				},
			},
		},
	}

	base, ok := profiles[0].DeepCopyObject().(client.Object)
	require.True(t, ok)
	require.NoError(t, NormalizeProfile(base))

	merged, err := MergeProfiles(profiles)
	require.NoError(t, err)
	require.NoError(t, NormalizeProfile(merged))

	require.True(t, reflect.DeepEqual(base, merged))
}
