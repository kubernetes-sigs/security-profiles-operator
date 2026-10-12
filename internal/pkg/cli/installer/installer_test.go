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

package installer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/installer/installerfakes"
)

func TestRun(t *testing.T) {
	t.Parallel()

	defaultOptions := func() *Options {
		options := Default()

		return options
	}

	apparmorProfile, err := os.ReadFile("../../../../examples/apparmorprofile.yaml")
	require.NoError(t, err)

	seccompProfile, err := os.ReadFile("../../../../examples/seccompprofile.yaml")
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		prepare func(*installerfakes.FakeImpl) *Options
		assert  func(*installerfakes.FakeImpl, error)
	}{
		{
			name: "successful apparmor install",
			prepare: func(mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorInstallProfileReturns(true, nil)

				return &Options{
					ProfilePath: "/foo",
				}
			},
			assert: func(mock *installerfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, "/foo", mock.ReadFileArgsForCall(0))
			},
		},
		{
			name: "insufficient permissions",
			prepare: func(mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(false)

				return defaultOptions()
			},
			assert: func(mock *installerfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, ErrAppArmorUnavailable)
			},
		},
		{
			name: "install failed",
			prepare: func(mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorInstallProfileReturns(false, errors.New("profile syntax error"))

				return defaultOptions()
			},
			assert: func(mock *installerfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "profile syntax error")
			},
		},
		{
			name: "unsupported profile type",
			prepare: func(mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(seccompProfile, nil)

				return defaultOptions()
			},
			assert: func(mock *installerfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "cannot install SeccompProfile profiles")
			},
		},
		{
			name: "invalid file",
			prepare: func(mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns([]byte{}, nil)

				return defaultOptions()
			},
			assert: func(mock *installerfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "failed to read")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &installerfakes.FakeImpl{}
			options := prepare(mock)

			sut := New(options, cli.Logger())
			sut.impl = mock

			err := sut.Run()
			assert(mock, err)
		})
	}
}

// TestPatchProfileName verifies which executable the installed profile
// confines: the one of the options, or the command on the PATH the profile is
// named after. The test sets the PATH for all its cases.
//
//nolint:paralleltest // see above
func TestPatchProfileName(t *testing.T) {
	dir := t.TempDir()
	command := filepath.Join(dir, "test-command")
	require.NoError(t, os.WriteFile(command, []byte("#!/bin/sh\n"), 0o700))
	t.Setenv("PATH", dir)

	for _, tc := range []struct {
		name           string
		profileName    string
		executablePath string
		want           string
		wantErr        bool
	}{
		{
			name:           "executable path of the options",
			profileName:    "test-command",
			executablePath: "/usr/bin/other",
			want:           "/usr/bin/other",
		},
		{name: "command on the PATH", profileName: "test-command", want: command},
		{name: "not a command", profileName: "my-profile", want: "my-profile"},
		{name: "empty name", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := &apparmorprofileapi.AppArmorProfile{}
			profile.Name = tc.profileName

			options := Default()
			options.ExecutablePath = tc.executablePath

			err := PatchProfileName(profile, options)
			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, profile.Name)
		})
	}
}
