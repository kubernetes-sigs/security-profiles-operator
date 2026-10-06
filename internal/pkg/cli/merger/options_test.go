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

package merger

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
				require.NoError(t, set.Parse([]string{"foo.yaml", "bar.yaml"}))
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name:    "failure: no profiles provided",
			prepare: func(set *flag.FlagSet) {},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{
			name: "failure: no filename provided",
			prepare: func(set *flag.FlagSet) {
				set.String(FlagOutputFile, "", "")
				require.NoError(t, set.Set(FlagOutputFile, ""))
				require.NoError(t, set.Parse([]string{"foo.yaml", "bar.yaml"}))
			},
			assert: func(err error) {
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

			_, err := FromContext(ctx)
			tc.assert(err)
		})
	}
}

func TestFromContextCheck(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		args      []string
		wantCheck bool
	}{
		{name: "default", args: []string{"foo.yaml"}},
		{name: "check", args: []string{"--" + FlagCheck, "foo.yaml"}, wantCheck: true},
		{name: "check set to false", args: []string{"--" + FlagCheck + "=false", "foo.yaml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ContinueOnError)
			set.Bool(FlagCheck, false, "")
			require.NoError(t, set.Parse(tc.args))

			options, err := FromContext(cli.NewContext(cli.NewApp(), set, nil))
			require.NoError(t, err)
			require.Equal(t, tc.wantCheck, options.check)
		})
	}
}
