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

package converter

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/converter/converterfakes"
)

func TestRun(t *testing.T) {
	t.Parallel()

	defaultOptions := func() *Options {
		options := Default()
		options.inputFile = "input.yaml"
		return options
	}

	for _, tc := range []struct {
		name           string
		input          string
		outputContains []string
	}{
		{
			name: "AppArmor CRD in enforce mode by default",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: AppArmorProfile
spec:
  abstract:
    filesystem:
      readOnlyPaths:
      - /dev/null
`,
			outputContains: []string{`deny /dev/null wl`, `flags=(enforce,attach_disconnected,mediate_deleted)`},
		},
		{
			name: "AppArmor CRD in enforce mode",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: AppArmorProfile
spec:
  complainMode: false
  abstract:
    filesystem:
      readOnlyPaths:
      - /dev/null
`,
			outputContains: []string{`deny /dev/null wl`, `flags=(enforce,attach_disconnected,mediate_deleted)`},
		},
		{
			name: "AppArmor CRD in complain mode",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: AppArmorProfile
spec:
  complainMode: true
  abstract:
    filesystem:
      readOnlyPaths:
      - /dev/null
`,
			outputContains: []string{`deny /dev/null wl`, `flags=(complain,attach_disconnected,mediate_deleted)`},
		},
		{
			name: "seccomp",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - foo
`,
			outputContains: []string{`"defaultAction": "SCMP_ACT_ERRNO"`},
		},
	} {
		input := tc.input
		outputContains := tc.outputContains
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &converterfakes.FakeImpl{}
			sut := New(defaultOptions())
			sut.impl = mock
			mock.ReadFileReturns([]byte(input), nil)

			err := sut.Run()
			require.NoError(t, err)
			_, actual, _ := mock.WriteFileArgsForCall(0)
			for _, contain := range outputContains {
				require.Contains(t, string(actual), contain)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		prepare func(*converterfakes.FakeImpl) *Options
		assert  func(*converterfakes.FakeImpl, error)
	}{
		{
			name: "input file not found",
			prepare: func(mock *converterfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, nil, errors.New("file not found"))
				return defaultOptions()
			},
			assert: func(mock *converterfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "file not found")
			},
		},
		{
			name: "input file is not yaml",
			prepare: func(mock *converterfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte("% this is not yaml"), nil)
				return defaultOptions()
			},
			assert: func(mock *converterfakes.FakeImpl, err error) {
				require.ErrorContains(t, err, "cannot parse yaml")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &converterfakes.FakeImpl{}
			options := prepare(mock)

			sut := New(options)
			sut.impl = mock

			err := sut.Run()
			assert(mock, err)
		})
	}
}
