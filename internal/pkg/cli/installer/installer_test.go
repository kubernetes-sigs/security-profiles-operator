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

	// A single document, the examples hold several profiles.
	seccompProfile := []byte("apiVersion: security-profiles-operator.x-k8s.io/v1\n" +
		"kind: SeccompProfile\nmetadata:\n  name: profile\n")

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *installerfakes.FakeImpl) *Options
		assert  func(*testing.T, *installerfakes.FakeImpl, error)
	}{
		{
			name: "successful apparmor install",
			prepare: func(_ *testing.T, mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorInstallProfileReturns(true, nil)

				return &Options{
					ProfilePath: "/foo",
				}
			},
			assert: func(t *testing.T, mock *installerfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "/foo", mock.ReadFileArgsForCall(0))
			},
		},
		{
			name: "insufficient permissions",
			prepare: func(_ *testing.T, mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(false)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *installerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrAppArmorUnavailable)
			},
		},
		{
			name: "install failed",
			prepare: func(_ *testing.T, mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorInstallProfileReturns(false, errors.New("profile syntax error"))

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *installerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "profile syntax error")
			},
		},
		{
			name: "unsupported profile type",
			prepare: func(_ *testing.T, mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns(seccompProfile, nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *installerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "cannot install SeccompProfile profiles")
			},
		},
		{
			name: "invalid file",
			prepare: func(_ *testing.T, mock *installerfakes.FakeImpl) *Options {
				mock.ReadFileReturns([]byte{}, nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *installerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "failed to read")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &installerfakes.FakeImpl{}
			options := prepare(t, mock)

			sut := New(options, cli.Logger())
			sut.impl = mock

			err := sut.Run()
			assert(t, mock, err)
		})
	}
}

// TestExecutable verifies which executable the installed profile
// confines: the one of the options, or the command on the PATH the profile is
// named after. The test sets the PATH for all its cases.
//
//nolint:paralleltest // see above
func TestExecutable(t *testing.T) {
	dir := t.TempDir()
	command := filepath.Join(dir, "test-command")
	require.NoError(t, os.WriteFile(command, []byte("#!/bin/sh\n"), 0o700))
	t.Setenv("PATH", dir)

	wd, err := os.Getwd()
	require.NoError(t, err)

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
		{
			name:           "relative executable path",
			profileName:    "p",
			executablePath: "rel/app",
			want:           filepath.Join(wd, "rel", "app"),
		},
		{
			// An executable argument is a path, never a command on the PATH.
			name:           "bare executable argument",
			profileName:    "p",
			executablePath: "test-command",
			want:           filepath.Join(wd, "test-command"),
		},
		{name: "not a command", profileName: "my-profile", want: "my-profile"},
		{name: "empty name", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := &apparmorprofileapi.AppArmorProfile{}
			profile.Name = tc.profileName

			options := Default()
			options.ExecutablePath = tc.executablePath

			_, err := executable(profile, options)
			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, profile.Name)
		})
	}
}

// TestAppArmorProfileUnresolvedName verifies the name earlier releases gave
// the profile of a command on the PATH: its path on the PATH, without
// resolving a symlink, and never the bare name, which may name an unrelated
// profile. The test sets the PATH.
func TestAppArmorProfileUnresolvedName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\n"), 0o700))

	link := filepath.Join(dir, "test-command")
	require.NoError(t, os.Symlink(target, link))
	t.Setenv("PATH", dir)

	content := []byte("apiVersion: security-profiles-operator.x-k8s.io/v1\n" +
		"kind: AppArmorProfile\nmetadata:\n  name: test-command\n")

	profile, unresolved, err := AppArmorProfile(content, Default(), "remove")
	require.NoError(t, err)

	wantTarget, err := filepath.EvalSymlinks(target)
	require.NoError(t, err)
	require.Equal(t, wantTarget, profile.Name)
	require.Equal(t, link, unresolved)

	options := Default()
	options.ExecutablePath = "rel/app"

	_, unresolved, err = AppArmorProfile(content, options, "remove")
	require.NoError(t, err)
	require.Equal(t, "rel/app", unresolved)
}
