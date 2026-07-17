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
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

func TestMergeFilesystem(t *testing.T) {
	t.Parallel()

	baseFS := apparmorprofileapi.AppArmorFsRules{
		ReadOnlyPaths:  []string{"/r/*"},
		WriteOnlyPaths: []string{"/w/*"},
		ReadWritePaths: []string{"/rw/*"},
	}

	testCases := []struct {
		name      string
		additions apparmorprofileapi.AppArmorFsRules
		merged    apparmorprofileapi.AppArmorFsRules
	}{
		{
			name:      "empty",
			additions: apparmorprofileapi.AppArmorFsRules{},
			merged:    baseFS,
		},
		{
			name: "matching",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/r/foo"},
				WriteOnlyPaths: []string{"/w/bar"},
				ReadWritePaths: []string{"/rw/baz"},
			},
			merged: baseFS,
		},
		{
			name: "subset",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/rw/foo"},
				WriteOnlyPaths: []string{"/rw/bar"},
			},
			merged: baseFS,
		},
		{
			name: "additive",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/w/foo"},
				WriteOnlyPaths: []string{"/r/bar"},
			},
			merged: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/r/*"},
				WriteOnlyPaths: []string{"/w/*"},
				ReadWritePaths: []string{"/r/bar", "/rw/*", "/w/foo"},
			},
		},
		{
			name: "additive2",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadWritePaths: []string{"/r/foo", "/w/foo"},
			},
			merged: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/r/*"},
				WriteOnlyPaths: []string{"/w/*"},
				ReadWritePaths: []string{"/r/foo", "/rw/*", "/w/foo"},
			},
		},
		{
			name: "new",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/r2/foo"},
				WriteOnlyPaths: []string{"/w2/bar"},
				ReadWritePaths: []string{"/rw2/baz"},
			},
			merged: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  []string{"/r/*", "/r2/foo"},
				WriteOnlyPaths: []string{"/w/*", "/w2/bar"},
				ReadWritePaths: []string{"/rw/*", "/rw2/baz"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := &mergeableAppArmorProfile{}
			base.Spec.Abstract = apparmorprofileapi.AppArmorAbstract{
				Filesystem: baseFS.DeepCopy(),
			}

			other := &mergeableAppArmorProfile{}
			other.Spec.Abstract = apparmorprofileapi.AppArmorAbstract{
				Filesystem: tc.additions.DeepCopy(),
			}

			err := base.merge(other)
			require.NoError(t, err)
			require.Equal(t, tc.merged, *base.Spec.Abstract.Filesystem)
		})
	}
}
