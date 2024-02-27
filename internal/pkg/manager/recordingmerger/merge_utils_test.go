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
	"sort"
	"testing"

	"github.com/containers/common/pkg/seccomp"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

func ifaceAsSortedSeccompProfile(iface mergeableProfile) *seccompprofile.SeccompProfile {
	prof, ok := iface.getProfile().(*seccompprofile.SeccompProfile)
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

func ifaceAsSortedSelinuxProfile(iface mergeableProfile) *selinuxprofileapi.SelinuxProfile {
	prof, ok := iface.getProfile().(*selinuxprofileapi.SelinuxProfile)
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
		prepare func(*testing.T) []mergeableProfile
		assert  func(profile mergeableProfile) error
	}{
		{
			name: "Two seccomp profiles",
			prepare: func(t *testing.T) []mergeableProfile {
				t.Helper()

				parts := []seccompprofile.SeccompProfile{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-abc",
						},
						Spec: seccompprofile.SeccompProfileSpec{
							BaseProfileName: "part1",
							DefaultAction:   seccomp.ActAllow,
							Syscalls: []*seccompprofile.Syscall{
								{
									Names:  []string{"a", "b", "c"},
									Action: seccomp.Action("foo"),
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-ced",
						},
						Spec: seccompprofile.SeccompProfileSpec{
							BaseProfileName: "part1",
							DefaultAction:   seccomp.ActAllow,
							Syscalls: []*seccompprofile.Syscall{
								{
									Names:  []string{"c", "e", "d"},
									Action: seccomp.Action("foo"),
								},
							},
						},
					},
				}

				partialSpecs := make([]mergeableProfile, len(parts))
				for i := range parts {
					var err error
					partialSpecs[i], err = newMergeableProfile(&parts[i])
					require.NoError(t, err)
				}
				return partialSpecs
			},
			assert: func(mergedProfIface mergeableProfile) error {
				t.Helper()

				mergedProf := ifaceAsSortedSeccompProfile(mergedProfIface)
				require.Equal(t, mergedProf.Spec.Syscalls[0].Action, seccomp.Action("foo"))
				require.Equal(t, mergedProf.Spec.Syscalls[0].Names, []string{"a", "b", "c"})
				require.Equal(t, mergedProf.Spec.Syscalls[1].Action, seccomp.Action("foo"))
				require.Equal(t, mergedProf.Spec.Syscalls[1].Names, []string{"c", "d", "e"})
				return nil
			},
		},
		{
			name: "Two selinux profiles",
			prepare: func(t *testing.T) []mergeableProfile {
				t.Helper()

				parts := []selinuxprofileapi.SelinuxProfile{
					{
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
					{
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

				partialSpecs := make([]mergeableProfile, len(parts))
				for i := range parts {
					var err error
					partialSpecs[i], err = newMergeableProfile(&parts[i])
					require.NoError(t, err)
				}
				return partialSpecs
			},
			assert: func(profile mergeableProfile) error {
				t.Helper()

				mergedProf := ifaceAsSortedSelinuxProfile(profile)
				require.Equal(t, mergedProf.Spec.Allow, selinuxprofileapi.Allow{
					"label_foo": {"oc_baz": {"do_baz"}, "oc_bar": {"do_bar"}, "oc_bar2": {"do_bar2"}, "oc_baz2": {"do_baz2"}},
					"label_aaa": {"oc_aaa": {"do_aaa"}, "oc_bbb": {"do_bbb"}},
				})
				return nil
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			partialProfiles := tc.prepare(t)
			mergedProfIface, err := mergeMergeableProfiles(partialProfiles)
			require.Nil(t, err)
			err = tc.assert(mergedProfIface)
			require.Nil(t, err)
		})
	}
}
