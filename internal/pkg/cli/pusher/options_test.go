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

package pusher

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
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
			assert: func(_ *Options, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "success with annotations",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagAnnotations, "")
				require.NoError(t, set.Set(FlagAnnotations, "foo:bar,hello:world"))
			},
			assert: func(res *Options, err error) {
				require.NoError(t, err)
				assert.Len(t, res.annotations, 2)
				assert.Equal(t, "bar", res.annotations["foo"])
				assert.Equal(t, "world", res.annotations["hello"])
			},
		},
		{
			name: "success one profile but no platform",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo"))
			},
			assert: func(res *Options, err error) {
				require.NoError(t, err)
				assert.Len(t, res.inputFiles, 1)
				assert.Equal(t, "foo", res.inputFiles[DefaultPlatform])
			},
		},
		{
			name: "success one platform but no profile",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo"))
			},
			assert: func(res *Options, err error) {
				require.NoError(t, err)
				assert.Len(t, res.inputFiles, 1)
				for k, v := range res.inputFiles {
					assert.Equal(t, "foo", k.OS)
					assert.Equal(t, DefaultInputFile, v)
				}
			},
		},
		{
			name: "success multiple profiles and platforms",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo,bar"))
				set.Var(cli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo,bar"))
			},
			assert: func(res *Options, err error) {
				require.NoError(t, err)
				assert.Len(t, res.inputFiles, 2)
				for k, v := range res.inputFiles {
					assert.Equal(t, v, k.OS)
				}
			},
		},
		{
			name:    "failure no image provided",
			prepare: func(set *flag.FlagSet) {},
			assert: func(_ *Options, err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure wrong annotation format",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagAnnotations, "")
				require.NoError(t, set.Set(FlagAnnotations, "foo"))
			},
			assert: func(_ *Options, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "failure amount of profiles and platforms does not match",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo,bar"))
				set.Var(cli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo,bar,baz"))
			},
			assert: func(_ *Options, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "failure multiple profiles but no platforms",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo,bar"))
			},
			assert: func(_ *Options, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "failure duplicate platforms",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo,foo"))
			},
			assert: func(_ *Options, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "failure parse platforms",
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(cli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "this/is/a/wrong/platform"))
			},
			assert: func(_ *Options, err error) {
				assert.Error(t, err)
			},
		},
	} {
		testPrepare := tc.prepare
		testAssert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			testPrepare(set)

			app := cli.NewApp()
			ctx := cli.NewContext(app, set, nil)

			options, err := FromContext(ctx)
			testAssert(options, err)
		})
	}
}
