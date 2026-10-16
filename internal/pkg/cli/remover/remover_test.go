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

package remover

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/installer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/remover/removerfakes"
)

func TestRun(t *testing.T) {
	t.Parallel()

	defaultOptions := func() *installer.Options {
		options := installer.Default()

		return options
	}

	apparmorProfile, err := os.ReadFile("../../../../examples/apparmorprofile.yaml")
	require.NoError(t, err)

	// A single document, the examples hold several profiles.
	seccompProfile := []byte("apiVersion: security-profiles-operator.x-k8s.io/v1\n" +
		"kind: SeccompProfile\nmetadata:\n  name: profile\n")

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *removerfakes.FakeImpl) *installer.Options
		assert  func(*testing.T, *removerfakes.FakeImpl, error)
	}{
		{
			name: "successful apparmor removal",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorRemoveProfileReturns(true, nil)

				return &installer.Options{
					ProfilePath: "/foo",
				}
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "/foo", mock.ReadFileArgsForCall(0))
			},
		},
		{
			// Earlier releases named the profile after the executable as
			// given, without resolving it.
			name: "removal under the unresolved name",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorRemoveProfileReturnsOnCall(0, false, nil)
				mock.AppArmorRemoveProfileReturnsOnCall(1, true, nil)

				return &installer.Options{ProfilePath: "/foo", ExecutablePath: "rel/app"}
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 2, mock.AppArmorRemoveProfileCallCount())

				_, first := mock.AppArmorRemoveProfileArgsForCall(0)
				require.True(t, filepath.IsAbs(first.GetName()))

				_, second := mock.AppArmorRemoveProfileArgsForCall(1)
				require.Equal(t, "rel/app", second.GetName())
			},
		},
		{
			// Nothing to remove keeps the exit code of the released versions.
			name: "nothing removed",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorRemoveProfileReturns(false, nil)

				return &installer.Options{ProfilePath: "/foo", ExecutablePath: "/usr/bin/app"}
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, 1, mock.AppArmorRemoveProfileCallCount(), "the name needs no resolving")
			},
		},
		{
			name: "insufficient permissions",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(false)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, installer.ErrAppArmorUnavailable)
			},
		},
		{
			name: "remove failed",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns(apparmorProfile, nil)
				mock.AppArmorEnabledReturns(true)
				mock.AppArmorRemoveProfileReturns(false, errors.New("profile syntax error"))

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "profile syntax error")
			},
		},
		{
			name: "unsupported profile type",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns(seccompProfile, nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "cannot remove SeccompProfile profiles")
			},
		},
		{
			name: "invalid file",
			prepare: func(_ *testing.T, mock *removerfakes.FakeImpl) *installer.Options {
				mock.ReadFileReturns([]byte{}, nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *removerfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "failed to read")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &removerfakes.FakeImpl{}
			options := prepare(t, mock)

			sut := New(options, cli.Logger())
			sut.impl = mock

			err := sut.Run()
			assert(t, mock, err)
		})
	}
}
