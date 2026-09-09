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

package puller

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/puller/pullerfakes"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(mock *pullerfakes.FakeImpl)
		assert  func(error)
	}{
		{
			name: "success",
			prepare: func(mock *pullerfakes.FakeImpl) {
				mock.PullReturns(&artifact.PullResult{}, nil)
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "failure on WriteFile",
			prepare: func(mock *pullerfakes.FakeImpl) {
				mock.PullReturns(&artifact.PullResult{}, nil)
				mock.WriteFileReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on Pull",
			prepare: func(mock *pullerfakes.FakeImpl) {
				mock.PullReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &pullerfakes.FakeImpl{}
			prepare(mock)

			sut := New(Default())
			sut.impl = mock

			err := sut.Run()
			assert(err)
		})
	}
}

func TestOutputFile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		outputFile    string
		outputFileSet bool
		runtimeFormat bool
		want          string
	}{
		{
			name:          "default location for a runtime format artifact",
			outputFile:    "/tmp/profile.yaml",
			runtimeFormat: true,
			want:          "/tmp/profile.json",
		},
		{
			name:       "default location for a profile CRD artifact",
			outputFile: "/tmp/profile.yaml",
			want:       "/tmp/profile.yaml",
		},
		{
			name:          "requested location is never changed",
			outputFile:    "/tmp/my-profile.yaml",
			outputFileSet: true,
			runtimeFormat: true,
			want:          "/tmp/my-profile.yaml",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			options := Default()
			options.outputFile = tc.outputFile
			options.outputFileSet = tc.outputFileSet

			require.Equal(t, tc.want, New(options).outputFile(tc.runtimeFormat))
		})
	}
}
