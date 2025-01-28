/*
Copyright 2024 The Kubernetes Authors.

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
		prepare func(*flag.FlagSet)
		assert  func(error)
	}{
		{ // Success
			prepare: func(set *flag.FlagSet) {
				require.NoError(t, set.Parse([]string{"foo.yaml", "bar.yaml"}))
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{ // failure: no profiles provided
			prepare: func(set *flag.FlagSet) {},
			assert: func(err error) {
				require.Error(t, err)
			},
		},
		{ // failure: no filename provided
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
		set := flag.NewFlagSet("", flag.ExitOnError)
		tc.prepare(set)

		app := cli.NewApp()
		ctx := cli.NewContext(app, set, nil)

		_, err := FromContext(ctx)
		tc.assert(err)
	}
}
