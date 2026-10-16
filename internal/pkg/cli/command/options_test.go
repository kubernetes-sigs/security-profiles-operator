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

package command

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
				require.True(t, options.DropSudoPrivileges)
			},
		},
		{
			name: "privileged",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.Bool(FlagPrivileged, false, "")
				require.NoError(t, set.Parse([]string{"--" + FlagPrivileged, "echo"}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.False(t, options.DropSudoPrivileges)
			},
		},
		{
			name: "privileged set to false",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.Bool(FlagPrivileged, false, "")
				require.NoError(t, set.Parse([]string{"--" + FlagPrivileged + "=false", "echo"}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, options.DropSudoPrivileges)
			},
		},
		{
			name:    "failure no command provided",
			prepare: func(*testing.T, *flag.FlagSet) {},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			prepare(t, set)

			app := cli.NewApp()
			ctx := cli.NewContext(app, set, nil)

			options, err := FromContext(ctx)
			assert(t, options, err)
		})
	}
}
