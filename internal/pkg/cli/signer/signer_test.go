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

package signer

import (
	"errors"
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/signer/signerfakes"
)

var errTest = errors.New("test")

func TestFromContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*flag.FlagSet)
		assert  func(*Options, error)
	}{
		{
			name: "success",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"registry.example.com/profiles/crun:v1"}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Equal(t, "registry.example.com/profiles/crun:v1", options.image)
				require.False(t, options.plainHTTP)
				require.False(t, options.oidcDeviceFlow)
			},
		},
		{
			name: "success with flags",
			prepare: func(set *flag.FlagSet) {
				set.Bool(FlagPlainHTTP, false, "")
				set.Bool(FlagOIDCDeviceFlow, false, "")
				require.NoError(t, set.Parse([]string{
					"--" + FlagPlainHTTP, "--" + FlagOIDCDeviceFlow, "localhost:5000/crun:v1",
				}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.True(t, options.plainHTTP)
				require.True(t, options.oidcDeviceFlow)
			},
		},
		{
			name:    "failure no image provided",
			prepare: func(*flag.FlagSet) {},
			assert: func(_ *Options, err error) {
				require.ErrorContains(t, err, "no image provided")
			},
		},
		{
			name: "failure too many images",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"a:v1", "b:v1"}))
			},
			assert: func(_ *Options, err error) {
				require.ErrorContains(t, err, "too many arguments")
			},
		},
		{
			name: "failure username without password",
			prepare: func(set *flag.FlagSet) {
				set.String(cli.FlagUsername, "", "")
				require.NoError(t, set.Parse([]string{"--" + cli.FlagUsername, "user", "a:v1"}))
			},
			assert: func(_ *Options, err error) {
				require.ErrorIs(t, err, cli.ErrIncompleteCredentials)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ContinueOnError)
			tc.prepare(set)

			options, err := FromContext(ucli.NewContext(ucli.NewApp(), set, nil))
			tc.assert(options, err)
		})
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		signErr error
		assert  func(*signerfakes.FakeImpl, error)
	}{
		{
			name: "success",
			assert: func(mock *signerfakes.FakeImpl, err error) {
				require.NoError(t, err)
				require.Equal(t, 1, mock.SignCallCount())

				_, image, username, password, opts := mock.SignArgsForCall(0)
				require.Equal(t, "registry.example.com/profiles/crun:v1", image)
				require.Equal(t, "user", username)
				require.Equal(t, "pass", password)
				require.Equal(t, &artifact.SignOptions{PlainHTTP: true, OIDCDeviceFlow: true}, opts)
			},
		},
		{
			name:    "failure",
			signErr: errTest,
			assert: func(_ *signerfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name:    "failure without identity",
			signErr: artifact.ErrNoInteractiveSignIn,
			assert: func(_ *signerfakes.FakeImpl, err error) {
				require.ErrorIs(t, err, artifact.ErrNoInteractiveSignIn)
				require.ErrorContains(t, err, "--"+FlagOIDCDeviceFlow)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &signerfakes.FakeImpl{}
			mock.SignReturns(tc.signErr)

			sut := New(&Options{
				image:          "registry.example.com/profiles/crun:v1",
				username:       "user",
				password:       "pass",
				plainHTTP:      true,
				oidcDeviceFlow: true,
			})
			sut.impl = mock

			tc.assert(mock, sut.Run())
		})
	}
}
