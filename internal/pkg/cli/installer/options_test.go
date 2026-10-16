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

package installer

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
			name: "success: profile and executable specified",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"profile.yml", "tail"}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, "tail", options.ExecutablePath)
				require.Equal(t, "profile.yml", options.ProfilePath)
			},
		},
		{
			name: "success: profile specified",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"profile.yml"}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, options.ExecutablePath)
				require.Equal(t, "profile.yml", options.ProfilePath)
			},
		},
		{
			name: "success: all defaults",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, options.ExecutablePath)
				require.Equal(t, DefaultProfileFile, options.ProfilePath)
			},
		},
		{
			name: "failure: too many args",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"profile.yml", "tail", "-f", "/dev/null"}))
			},
			assert: func(t *testing.T, options *Options, err error) {
				t.Helper()

				require.Error(t, err)
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
