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

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
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
metadata:
  name: test
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
metadata:
  name: test
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
metadata:
  name: test
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
			name: "AppArmor CRD with deprecated ptrace rules",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: AppArmorProfile
metadata:
  name: legacy
spec:
  abstract:
    filesystem:
      readOnlyPaths:
      - ptrace (read),
`,
			outputContains: []string{`ptrace (read),`},
			logContains:    `profile "legacy": DEPRECATED: ptrace rules`,
		},
		{
			name: "AppArmor CRD with a directory traversal",
			input: `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: AppArmorProfile
metadata:
  name: traversal
spec:
  abstract:
    filesystem:
      readOnlyPaths:
      - /usr/../etc/hosts
`,
			outputContains: []string{`/usr/../etc/hosts r,`},
			logContains:    `profile "traversal": spec.abstract.filesystem paths with a directory traversal`,
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
		prepare func(*testing.T, *converterfakes.FakeImpl) *Options
		assert  func(*testing.T, *converterfakes.FakeImpl, error)
	}{
		{
			name: "input file not found",
			prepare: func(_ *testing.T, mock *converterfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, nil, errors.New("file not found"))

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *converterfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "file not found")
			},
		},
		{
			name: "input file is not yaml",
			prepare: func(_ *testing.T, mock *converterfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte("% this is not yaml"), nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *converterfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorIs(t, err, artifact.ErrDecodeYAML)
			},
		},
		{
			name: "AppArmor CRD without a name",
			prepare: func(_ *testing.T, mock *converterfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte(
					"apiVersion: security-profiles-operator.x-k8s.io/v1\nkind: AppArmorProfile\n",
				), nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *converterfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "profile has no name")
				require.Zero(t, mock.WriteFileCallCount())
			},
		},
		{
			name: "unsupported kind",
			prepare: func(_ *testing.T, mock *converterfakes.FakeImpl) *Options {
				mock.ReadFileReturnsOnCall(0, []byte(
					"apiVersion: security-profiles-operator.x-k8s.io/v1\nkind: SelinuxProfile\n",
				), nil)

				return defaultOptions()
			},
			assert: func(t *testing.T, mock *converterfakes.FakeImpl, err error) {
				t.Helper()

				require.ErrorContains(t, err, "cannot convert SelinuxProfile profiles")
				require.NotContains(t, err.Error(), "*v1.")
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &converterfakes.FakeImpl{}
			options := prepare(t, mock)

			sut := New(options)
			sut.impl = mock

			err := sut.Run()
			assert(t, mock, err)
		})
	}
}
