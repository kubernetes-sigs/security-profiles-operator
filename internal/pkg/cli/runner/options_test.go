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

package runner

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
		assert  func(error)
	}{
		{
			name: "success",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},

		{
			name:    "failure no command provided",
			prepare: func(set *flag.FlagSet) {},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure unsupported type",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagType, "", "")
				require.NoError(t, set.Set(FlagType, "wrong"))
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure no filename provided",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagProfile, "", "")
				require.NoError(t, set.Set(FlagProfile, ""))
			},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			prepare(set)

			app := cli.NewApp()
			ctx := cli.NewContext(app, set, nil)

			_, err := FromContext(ctx)
			assert(err)
		})
	}
}

// TestFromContextPrivileged verifies that spoc run drops the sudo privileges
// unless --privileged is set, like spoc record.
func TestFromContextPrivileged(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		args     []string
		wantDrop bool
	}{
		{name: "default", args: []string{"echo"}, wantDrop: true},
		{name: "privileged", args: []string{"--" + FlagPrivileged, "echo"}},
		{name: "privileged false", args: []string{"--" + FlagPrivileged + "=false", "echo"}, wantDrop: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ContinueOnError)
			set.Bool(FlagPrivileged, false, "")
			require.NoError(t, set.Parse(tc.args))

			options, err := FromContext(cli.NewContext(cli.NewApp(), set, nil))
			require.NoError(t, err)
			require.Equal(t, tc.wantDrop, options.commandOptions.DropSudoPrivileges)
		})
	}
}
