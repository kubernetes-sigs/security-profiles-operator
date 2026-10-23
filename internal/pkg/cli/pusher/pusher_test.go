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

package pusher

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/pusher/pusherfakes"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, mock *pusherfakes.FakeImpl)
		assert  func(*testing.T, error)
	}{
		{
			name:    "success",
			prepare: func(_ *testing.T, mock *pusherfakes.FakeImpl) {},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			name: "failure on Push",
			prepare: func(_ *testing.T, mock *pusherfakes.FakeImpl) {
				mock.PushReturns(errTest)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on signing after the push",
			prepare: func(_ *testing.T, mock *pusherfakes.FakeImpl) {
				mock.PushReturns(&artifact.UnsignedError{
					Reference: "registry.example.com/profiles/crun@sha256:1234",
					Err:       errTest,
				})
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
				require.ErrorContains(t, err, "spoc sign registry.example.com/profiles/crun@sha256:1234")
			},
		},
		{
			name: "failure without identity",
			prepare: func(_ *testing.T, mock *pusherfakes.FakeImpl) {
				mock.PushReturns(artifact.ErrNoInteractiveSignIn)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, artifact.ErrNoInteractiveSignIn)
				require.ErrorContains(t, err, "--"+FlagOIDCDeviceFlow)
				require.ErrorContains(t, err, "--"+FlagDisableSigning)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &pusherfakes.FakeImpl{}
			prepare(t, mock)

			sut := New(Default())
			sut.impl = mock

			err := sut.Run()
			assert(t, err)
		})
	}
}

func TestWithSigningHint(t *testing.T) {
	t.Parallel()

	unsigned := &artifact.UnsignedError{Reference: "registry/profile@sha256:abc", Err: errTest}

	err := withSigningHint(unsigned, false, false)
	require.ErrorIs(t, err, errTest)
	require.ErrorContains(t, err, "`spoc sign registry/profile@sha256:abc`")
	require.NotContains(t, err.Error(), "credentials")

	// The registry of the push is only reachable over plain HTTP.
	err = withSigningHint(unsigned, true, false)
	require.ErrorIs(t, err, errTest)
	require.ErrorContains(t, err, "`spoc sign --"+FlagPlainHTTP+" registry/profile@sha256:abc`")

	// The registry of the push needs credentials.
	err = withSigningHint(unsigned, false, true)
	require.ErrorContains(t, err, "the registry credentials of the push")

	err = withSigningHint(artifact.ErrNoInteractiveSignIn, false, false)
	require.ErrorIs(t, err, artifact.ErrNoInteractiveSignIn)
	require.ErrorContains(t, err, "--"+FlagOIDCDeviceFlow)
	require.ErrorContains(t, err, "--"+FlagDisableSigning)

	require.Equal(t, errTest, withSigningHint(errTest, false, false))
}
