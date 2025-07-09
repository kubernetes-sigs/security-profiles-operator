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

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
)

func TestAppArmorGlobToRegex(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		globPattern string
		wantRegex   string
	}{
		{
			name:        "Basic File Match",
			globPattern: "/bin/ls",
			wantRegex:   `^/bin/ls$`,
		},
		{
			name:        "Single Wildcard",
			globPattern: "/usr/bin/*",
			wantRegex:   `^/usr/bin/[^/\000]*$`,
		},
		{
			name:        "Double Wildcard",
			globPattern: "/home/**/docs",
			wantRegex:   `^/home/[^\000]*/docs$`,
		},
		{
			name:        "Character Class",
			globPattern: "/var/log/{kern.log,syslog}",
			wantRegex:   `^/var/log/(kern\.log|syslog)$`,
		},
		{
			name:        "Question Mark",
			globPattern: "/tmp/file?.txt",
			wantRegex:   `^/tmp/file[^/]\.txt$`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := appArmorGlobToRegex(tc.globPattern)
			require.NoError(t, err)
			require.Equal(t, tc.wantRegex, result.String())
		})
	}
}

func Test_appArmorPathSet(t *testing.T) {
	t.Parallel()

	m := newAppArmorPathSet(&[]string{
		"/foo/*",
		"/bar",
	})

	require.True(t, m.Matches("/foo/baz"))
	require.True(t, m.Matches("/bar"))
	require.False(t, m.Matches("/baz"))

	p := m.PopMatching("/foo/baz")
	require.Equal(t, "/foo/*", *p)
	require.False(t, m.Matches("/foo/baz"))

	p = m.PopMatching("/foo/baz")
	require.Nil(t, p)

	m.Add("/baz**")
	require.True(t, m.Matches("/baz/qux"))

	require.Equal(t, []string{"/bar", "/baz**"}, *m.Patterns())
}

func TestMergeFilesystem(t *testing.T) {
	t.Parallel()

	base := &apparmorprofileapi.AppArmorAbstract{
		Filesystem: &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths:  &[]string{"/r/*"},
			WriteOnlyPaths: &[]string{"/w/*"},
			ReadWritePaths: &[]string{"/rw/*"},
		},
	}

	testCases := []struct {
		name      string
		additions apparmorprofileapi.AppArmorFsRules
		merged    apparmorprofileapi.AppArmorFsRules
	}{
		{
			name:      "empty",
			additions: apparmorprofileapi.AppArmorFsRules{},
			merged:    *base.Filesystem,
		},
		{
			name: "matching",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  &[]string{"/r/foo"},
				WriteOnlyPaths: &[]string{"/w/bar"},
				ReadWritePaths: &[]string{"/rw/baz"},
			},
			merged: *base.Filesystem,
		},
		{
			name: "subset",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  &[]string{"/rw/foo"},
				WriteOnlyPaths: &[]string{"/rw/bar"},
			},
			merged: *base.Filesystem,
		},
		{
			name: "additive",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  &[]string{"/w/foo"},
				WriteOnlyPaths: &[]string{"/r/bar"},
			},
			merged: apparmorprofileapi.AppArmorFsRules{
				ReadWritePaths: &[]string{"/r/*", "/rw/*", "/w/*"},
			},
		},
		{
			name: "additive2",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadWritePaths: &[]string{"/r/foo", "/w/foo"},
			},
			merged: apparmorprofileapi.AppArmorFsRules{
				ReadWritePaths: &[]string{"/r/*", "/rw/*", "/w/*"},
			},
		},
		{
			name: "new",
			additions: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  &[]string{"/r2/foo"},
				WriteOnlyPaths: &[]string{"/w2/bar"},
				ReadWritePaths: &[]string{"/rw2/baz"},
			},
			merged: apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths:  &[]string{"/r/*", "/r2/foo"},
				WriteOnlyPaths: &[]string{"/w/*", "/w2/bar"},
				ReadWritePaths: &[]string{"/rw/*", "/rw2/baz"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := base.DeepCopy()
			mergeFilesystem(b, &apparmorprofileapi.AppArmorAbstract{
				Filesystem: &tc.additions,
			})
			require.Equal(t, *b.Filesystem, tc.merged)
		})
	}
}

func TestMergeBools(t *testing.T) {
	t.Parallel()

	True := true
	False := false

	require.True(t, *mergeBools(&True, &True))
	require.True(t, *mergeBools(&True, nil))
	require.True(t, *mergeBools(nil, &True))
	require.True(t, *mergeBools(&True, &False))
	require.False(t, *mergeBools(&False, &False))
	require.False(t, *mergeBools(&False, nil))
	require.Nil(t, mergeBools(nil, nil))
}
