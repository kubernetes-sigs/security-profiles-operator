/*
Copyright 2020 The Kubernetes Authors.

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

package seccomp_test

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/seccomp-operator/internal/pkg/node/seccomp"
	"sigs.k8s.io/seccomp-operator/internal/pkg/node/seccomp/seccompfakes"
)

var errTest error = errors.New("")

func TestIsSupported(t *testing.T) {
	for _, tc := range []struct {
		prepare  func(mock *seccompfakes.FakeVerifier)
		expected bool
	}{
		{ // success via status file parse
			prepare: func(mock *seccompfakes.FakeVerifier) {
				mock.ParseStatusFileReturns(
					map[string]string{"Seccomp": "0"}, nil,
				)
			},
			expected: true,
		},
		{ // success via prctl
			prepare: func(mock *seccompfakes.FakeVerifier) {
				mock.ParseStatusFileReturns(nil, errTest)
			},
			expected: true,
		},
		{ // failure via status file parse
			prepare: func(mock *seccompfakes.FakeVerifier) {
				mock.ParseStatusFileReturns(nil, errTest)
				mock.PrctlReturns(unix.EINVAL)
			},
			expected: false,
		},
		{ // failure via prctl
			prepare: func(mock *seccompfakes.FakeVerifier) {
				mock.PrctlReturns(unix.EINVAL)
			},
			expected: false,
		},
	} {
		sut := seccomp.New()
		mock := &seccompfakes.FakeVerifier{}
		tc.prepare(mock)
		sut.SetVerifier(mock)
		require.Equal(t, tc.expected, sut.IsSupported(log.Log))
	}
}

func TestParseStatusFile(t *testing.T) {
	for _, tc := range []struct {
		getFilePath func() (string, func())
		shouldErr   bool
		expected    map[string]string
	}{
		{ // success
			getFilePath: func() (string, func()) {
				tempFile, err := ioutil.TempFile("", "parse-status-file-")
				require.Nil(t, err)

				// Valid entry
				_, err = tempFile.WriteString("Seccomp:   0\n")
				require.Nil(t, err)

				// Unparsable entry
				_, err = tempFile.WriteString("wrong")
				require.Nil(t, err)

				return tempFile.Name(), func() {
					require.Nil(t, os.RemoveAll(tempFile.Name()))
				}
			},
			shouldErr: false,
			expected:  map[string]string{"Seccomp": "0"},
		},
		{ // error opening file
			getFilePath: func() (string, func()) {
				tempFile, err := ioutil.TempFile("", "parse-status-file-")
				require.Nil(t, err)

				require.Nil(t, os.RemoveAll(tempFile.Name()))

				return tempFile.Name(), func() {}
			},
			shouldErr: true,
		},
	} {
		filePath, cleanup := tc.getFilePath()
		defer cleanup()
		res, err := seccomp.ParseStatusFile(log.Log, filePath)
		if tc.shouldErr {
			require.NotNil(t, err)
		} else {
			require.Equal(t, tc.expected, res)
		}
	}
}
