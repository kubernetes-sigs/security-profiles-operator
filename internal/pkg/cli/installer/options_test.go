/*
Copyright 2025 The Kubernetes Authors.

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
		prepare func(*flag.FlagSet)
		assert  func(*Options, error)
	}{
		{ // Success: profile and executable specified
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"profile.yml", "tail"}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Equal(t, "tail", options.ExecutablePath)
				require.Equal(t, "profile.yml", options.ProfilePath)
			},
		},
		{ // Success: profile specified
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"profile.yml"}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Empty(t, options.ExecutablePath)
				require.Equal(t, "profile.yml", options.ProfilePath)
			},
		},
		{ // Success: all defaults
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{}))
			},
			assert: func(options *Options, err error) {
				require.NoError(t, err)
				require.Empty(t, options.ExecutablePath)
				require.Equal(t, DefaultProfileFile, options.ProfilePath)
			},
		},
		{ // failure: too many args
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"profile.yml", "tail", "-f", "/dev/null"}))
			},
			assert: func(options *Options, err error) {
				require.Error(t, err)
			},
		},
	} {
		set := flag.NewFlagSet("", flag.ExitOnError)
		tc.prepare(set)

		app := cli.NewApp()
		ctx := cli.NewContext(app, set, nil)

		options, err := FromContext(ctx)
		tc.assert(options, err)
	}
}
