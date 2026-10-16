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

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
)

func TestFromContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*testing.T, *flag.FlagSet)
		assert  func(*testing.T, error)
	}{
		{
			name: "success",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},

		{
			name:    "failure no command provided",
			prepare: func(*testing.T, *flag.FlagSet) {},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorContains(t, err, "get command options")
			},
		},
		{
			name: "failure unsupported type",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagType, "", "")
				require.NoError(t, set.Parse([]string{"--" + FlagType, "wrong", "echo"}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.EqualError(t, err, "unsupported "+FlagType+": wrong")
			},
		},
		{
			name: "failure no filename provided",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(FlagProfile, "", "")
				require.NoError(t, set.Parse([]string{"--" + FlagProfile, "", "echo"}))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.EqualError(t, err, "no profile provided")
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

			_, err := FromContext(ctx)
			assert(t, err)
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
		{name: "privileged", args: []string{"--" + command.FlagPrivileged, "echo"}},
		{name: "privileged false", args: []string{"--" + command.FlagPrivileged + "=false", "echo"}, wantDrop: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ContinueOnError)
			set.Bool(command.FlagPrivileged, false, "")
			require.NoError(t, set.Parse(tc.args))

			options, err := FromContext(cli.NewContext(cli.NewApp(), set, nil))
			require.NoError(t, err)
			require.Equal(t, tc.wantDrop, options.commandOptions.DropSudoPrivileges)
		})
	}
}
