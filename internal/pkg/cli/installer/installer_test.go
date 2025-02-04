//go:build linux
// +build linux

/*
Copyright 2025 The Kubernetes Authors.

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
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

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
				require.ErrorContains(t, err, "insufficient permissions")
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
				require.ErrorContains(t, err, "cannot install")
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

			sut := New(options, logr.New(&cli.LogSink{}))
			sut.impl = mock

			err := sut.Run()
			assert(mock, err)
		})
	}
}
