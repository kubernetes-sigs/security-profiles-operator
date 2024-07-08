/*
Copyright 2023 The Kubernetes Authors.

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

package puller

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
				set.String(FlagUsername, "", "")
				require.NoError(t, set.Set(FlagUsername, "username"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(opts *Options, err error) {
				require.NoError(t, err)
				require.False(t, opts.disableSignatureVerification)
			},
		},
		{
			name: "success with verify signature disabled",
			prepare: func(set *flag.FlagSet) {
				set.Bool(FlagDisableSignatureVerification, true, "")
				require.NoError(t, set.Set(FlagDisableSignatureVerification, "true"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(opts *Options, err error) {
				require.NoError(t, err)
				require.True(t, opts.disableSignatureVerification)
			},
		},
		{
			name: "failure no image provided",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Set(FlagOutputFile, ""))
			},
			assert: func(_ *Options, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure no output file provided",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Set(FlagOutputFile, ""))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(_ *Options, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure parse platform",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagPlatform, "", "")
				require.NoError(t, set.Set(FlagPlatform, "os//var"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(_ *Options, err error) {
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

			opts, err := FromContext(ctx)
			assert(opts, err)
		})
	}
}
