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

package recorder

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
)

func TestFromContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *flag.FlagSet)
		assert  func(*testing.T, *Options, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, DefaultBaseSyscalls, options.baseSyscalls)
				require.False(t, options.noProcStart)
				require.True(t, options.commandOptions.DropSudoPrivileges)
			},
		},
		{
			name: "boolean flags set",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.Bool(FlagNoBaseSyscalls, false, "")
				set.Bool(FlagNoProcStart, false, "")
				set.Bool(command.FlagPrivileged, false, "")
				require.NoError(t, set.Parse([]string{
					"--" + FlagNoBaseSyscalls, "--" + FlagNoProcStart, "--" + command.FlagPrivileged, "echo",
				}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Nil(t, options.baseSyscalls)
				require.True(t, options.noProcStart)
				require.False(t, options.commandOptions.DropSudoPrivileges)
			},
		},
		{
			name: "boolean flags set to false",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.Bool(FlagNoBaseSyscalls, false, "")
				set.Bool(FlagNoProcStart, false, "")
				set.Bool(command.FlagPrivileged, false, "")
				require.NoError(t, set.Parse([]string{
					"--" + FlagNoBaseSyscalls + "=false",
					"--" + FlagNoProcStart + "=false",
					"--" + command.FlagPrivileged + "=false",
					"echo",
				}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, DefaultBaseSyscalls, options.baseSyscalls)
				require.False(t, options.noProcStart)
				require.True(t, options.commandOptions.DropSudoPrivileges)
			},
		},
		{
			name:    "failure: no command provided",
			prepare: func(*testing.T, *flag.FlagSet) {},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "get command options")
			},
		},
		{
			name: "failure: unsupported type",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagType, "", "")
				require.NoError(t, set.Parse([]string{"--" + FlagType, "wrong", "echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.EqualError(t, err, "unsupported "+FlagType+": wrong")
			},
		},
		{
			name: "failure: no filename provided",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Parse([]string{"--" + FlagOutputFile, "", "echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.EqualError(t, err, "no filename provided")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			tc.prepare(t, set)

			app := cli.NewApp()
			ctx := cli.NewContext(app, set, nil)

			options, err := FromContext(ctx)
			tc.assert(t, options, err)
		})
	}
}
