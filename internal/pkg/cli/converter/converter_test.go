//go:build linux && !no_bpf

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

package converter

import (
	"bytes"
	"errors"
	"log"
	"os"
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
		name              string
		input             string
		outputContains    []string
		outputNotContains []string
		logContains       string
	}{
		{
			name: "AppArmor CRD in enforce mode by default",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
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
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: AppArmorProfile
spec:
  mode: Enforce
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
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: AppArmorProfile
spec:
  mode: Complain
  abstract:
    filesystem:
      readOnlyPaths:
      - /dev/null
`,
			outputContains: []string{`/dev/null r,`, `flags=(complain,attach_disconnected,mediate_deleted)`},
		},
		{
			name: "seccomp",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
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
		{
			name: "seccomp without CRD only fields",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
spec:
  state: Enabled
  baseProfileName: runc-v1.5.1
  defaultAction: SCMP_ACT_ERRNO
`,
			outputContains:    []string{`"defaultAction": "SCMP_ACT_ERRNO"`},
			outputNotContains: []string{`"state"`, `"baseProfileName"`},
			logContains:       "Dropping base profile",
		},
		{
			name: "seccomp with listener fields",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  listenerPath: /var/run/security-profiles-operator/agent.sock
  listenerMetadata: some-metadata
`,
			outputContains:    []string{`"defaultAction": "SCMP_ACT_ERRNO"`},
			outputNotContains: []string{`"listenerPath"`, `"listenerMetadata"`},
			logContains:       "Dropping the listener fields",
		},
		{
			name: "seccomp with listener metadata only",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  listenerMetadata: some-metadata
`,
			outputContains:    []string{`"defaultAction": "SCMP_ACT_ERRNO"`},
			outputNotContains: []string{`"listenerMetadata"`},
			logContains:       "Dropping the listener fields",
		},
		{
			name: "seccomp using the notifier",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  listenerPath: /var/run/security-profiles-operator/agent.sock
  syscalls:
  - action: SCMP_ACT_NOTIFY
    names:
    - openat
`,
			outputNotContains: []string{`"listenerPath"`},
			logContains:       "has to provide a listener path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			log.SetOutput(logs)

			defer log.SetOutput(os.Stderr)

			mock := &converterfakes.FakeImpl{}
			sut := New(defaultOptions())
			sut.impl = mock
			mock.ReadFileReturns([]byte(tc.input), nil)

			err := sut.Run()
			require.NoError(t, err)

			_, actual, _ := mock.WriteFileArgsForCall(0)
			for _, contain := range tc.outputContains {
				require.Contains(t, string(actual), contain)
			}

			for _, contain := range tc.outputNotContains {
				require.NotContains(t, string(actual), contain)
			}

			if tc.logContains != "" {
				require.Contains(t, logs.String(), tc.logContains)
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
