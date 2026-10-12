//go:build linux

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

package util

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/require"
)

func TestUname(t *testing.T) {
	t.Parallel()

	arch, version, err := Uname()
	require.NoError(t, err)
	require.True(t, version.GT(semver.Version{Major: 0, Minor: 0, Patch: 0}))
	require.NotEmpty(t, arch)
}

func TestParseRelease(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		release string
		want    semver.Version
		wantErr bool
	}{
		{release: "6.6.93", want: semver.Version{Major: 6, Minor: 6, Patch: 93}},
		{release: "6.6.93+", want: semver.Version{Major: 6, Minor: 6, Patch: 93}},
		{release: "6.6.93+extra", want: semver.Version{Major: 6, Minor: 6, Patch: 93}},
		{release: "5.14.0-427.13.1.el9_4.x86_64", want: semver.Version{Major: 5, Minor: 14}},
		{release: "6.8.0-45-generic", want: semver.Version{Major: 6, Minor: 8}},
		{release: "6.12.0-rc1", want: semver.Version{Major: 6, Minor: 12}},
		{release: "6.1", want: semver.Version{Major: 6, Minor: 1}},
		{release: "", wantErr: true},
		{release: "linux", wantErr: true},
	} {
		t.Run(tc.release, func(t *testing.T) {
			t.Parallel()

			got, err := parseRelease(tc.release)
			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
