//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2024 The Kubernetes Authors.

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

package merger

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/merger/mergerfakes"
)

const SeccompA = `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - foo
`

const SeccompB = `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - bar
`

const SeccompMerged = `apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  creationTimestamp: null
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - foo
  - action: SCMP_ACT_ALLOW
    names:
    - bar
status: {}
`

const SelinuxA = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: SelinuxProfile
spec:
  inherit:
    - name: container
  allow:
    var_log_t:
      dir:
        - open
`

func TestRun(t *testing.T) {
	t.Parallel()

	defaultOptions := func() *Options {
		options := Default()
		options.inputFiles = []string{"foo.yaml", "bar.yaml"}
		return options
	}

	for _, tc := range []struct {
		name    string
		prepare func(*mergerfakes.FakeImpl) *Options
		assert  func(*mergerfakes.FakeImpl, error)
	}{
		{
			name: "successful seccomp merge",
			prepare: func(mock *mergerfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte(SeccompA), nil)
				mock.ReadFileReturnsOnCall(1, []byte(SeccompB), nil)
				return defaultOptions()
			},
			assert: func(mock *mergerfakes.FakeImpl, err error) {
				require.NoError(t, err)
				_, merged, _ := mock.WriteFileArgsForCall(0)
				require.Equal(t, SeccompMerged, string(merged))
			},
		},
		{
			name: "cannot merge different formats",
			prepare: func(mock *mergerfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte(SeccompA), nil)
				mock.ReadFileReturnsOnCall(1, []byte(SelinuxA), nil)
				return defaultOptions()
			},
			assert: func(mock *mergerfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "cannot merge SeccompProfile with *recordingmerger.MergeableSelinuxProfile")
				require.Equal(t, 0, mock.WriteFileCallCount())
			},
		},
		{
			name: "input file not found",
			prepare: func(mock *mergerfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, nil, errors.New("file not found"))
				return defaultOptions()
			},
			assert: func(mock *mergerfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "open profile: file not found")
			},
		},
		{
			name: "input file is not yaml",
			prepare: func(mock *mergerfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte("% this is not yaml"), nil)
				return defaultOptions()
			},
			assert: func(mock *mergerfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "cannot parse yaml")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &mergerfakes.FakeImpl{}
			options := prepare(mock)

			sut := New(options)
			sut.impl = mock

			err := sut.Run()
			assert(mock, err)
		})
	}
}
