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
)

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
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Equal(t, DefaultBaseSyscalls, options.baseSyscalls)
				require.False(t, options.noProcStart)
				require.True(t, options.commandOptions.DropSudoPrivileges)
			},
		},
		{
			name: "boolean flags set",
			prepare: func(set *flag.FlagSet) {
				set.Bool(FlagNoBaseSyscalls, false, "")
				set.Bool(FlagNoProcStart, false, "")
				set.Bool(FlagPrivileged, false, "")
				require.NoError(t, set.Parse([]string{
					"--" + FlagNoBaseSyscalls, "--" + FlagNoProcStart, "--" + FlagPrivileged, "echo",
				}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Nil(t, options.baseSyscalls)
				require.True(t, options.noProcStart)
				require.False(t, options.commandOptions.DropSudoPrivileges)
			},
		},
		{
			name: "boolean flags set to false",
			prepare: func(set *flag.FlagSet) {
				set.Bool(FlagNoBaseSyscalls, false, "")
				set.Bool(FlagNoProcStart, false, "")
				set.Bool(FlagPrivileged, false, "")
				require.NoError(t, set.Parse([]string{
					"--" + FlagNoBaseSyscalls + "=false",
					"--" + FlagNoProcStart + "=false",
					"--" + FlagPrivileged + "=false",
					"echo",
				}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Equal(t, DefaultBaseSyscalls, options.baseSyscalls)
				require.False(t, options.noProcStart)
				require.True(t, options.commandOptions.DropSudoPrivileges)
			},
		},
		{
			name:    "failure: no command provided",
			prepare: func(set *flag.FlagSet) {},
			assert: func(_ *Options, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure: unsupported type",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagType, "", "")
				require.NoError(t, set.Set(FlagType, "wrong"))
			},
			assert: func(_ *Options, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure: no filename provided",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Set(FlagOutputFile, ""))
			},
			assert: func(_ *Options, err error) {
				require.Error(t, err)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			tc.prepare(set)

			app := cli.NewApp()
			ctx := cli.NewContext(app, set, nil)

			options, err := FromContext(ctx)
			tc.assert(options, err)
		})
	}
}
