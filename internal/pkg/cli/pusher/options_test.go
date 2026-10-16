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

package pusher

import (
	"flag"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
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
			assert: func(t *testing.T, res *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, map[*v1.Platform]string{nil: DefaultInputFile}, res.inputFiles)
			},
		},
		{
			name: "failure username without password",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.String(cli.FlagUsername, "", "")
				require.NoError(t, set.Set(cli.FlagUsername, "username"))
				require.NoError(t, set.Parse([]string{"echo"}))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorIs(t, err, cli.ErrIncompleteCredentials)
			},
		},
		{
			name: "success with annotations",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(&annotationsFlag{}, FlagAnnotations, "")
				require.NoError(t, set.Set(FlagAnnotations,
					"foo:bar,hello:world,org.opencontainers.image.created:2026-09-11T07:00:00Z",
				))
			},
			assert: func(t *testing.T, res *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, res.annotations, 3)
				assert.Equal(t, "bar", res.annotations["foo"])
				assert.Equal(t, "world", res.annotations["hello"])
				assert.Equal(t, "2026-09-11T07:00:00Z", res.annotations["org.opencontainers.image.created"])
			},
		},
		{
			name: "success one profile but no platform",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo"))
			},
			assert: func(t *testing.T, res *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, res.inputFiles, 1)
				assert.Equal(t, map[*v1.Platform]string{nil: "foo"}, res.inputFiles)
			},
		},
		{
			name: "success one platform but no profile",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo"))
			},
			assert: func(t *testing.T, res *Options, err error) {
				t.Helper()

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
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo,bar"))
				set.Var(ucli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo,bar"))
			},
			assert: func(t *testing.T, res *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, res.inputFiles, 2)

				for k, v := range res.inputFiles {
					assert.Equal(t, v, k.OS)
				}
			},
		},
		{
			name:    "failure no image provided",
			prepare: func(*testing.T, *flag.FlagSet) {},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			name: "failure wrong annotation format",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(&annotationsFlag{}, FlagAnnotations, "")
				require.NoError(t, set.Set(FlagAnnotations, "foo"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "failure empty annotation key",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(&annotationsFlag{}, FlagAnnotations, "")
				require.NoError(t, set.Set(FlagAnnotations, " :value"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "empty annotation key")
			},
		},
		{
			name: "success with device flow",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				set.Bool(FlagOIDCDeviceFlow, false, "")
				require.NoError(t, set.Parse([]string{"--" + FlagOIDCDeviceFlow, "echo"}))
			},
			assert: func(t *testing.T, res *Options, err error) {
				t.Helper()

				require.NoError(t, err)
				require.True(t, res.oidcDeviceFlow)
			},
		},
		{
			name: "failure amount of profiles and platforms does not match",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo,bar"))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo,bar,baz"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "failure multiple profiles but no platforms",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagProfiles, "")
				require.NoError(t, set.Set(FlagProfiles, "foo,bar"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "failure multiple platforms but no profiles",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "linux/amd64,linux/arm64"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "2 platforms provided but no profiles")
			},
		},
		{
			name: "failure duplicate platforms",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "foo,foo"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
		{
			name: "failure duplicate platforms in different spellings",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "linux/amd64,linux/amd64:"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "duplicate platforms defined")
			},
		},
		{
			name: "failure duplicate platforms with the default variant",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "linux/arm64,linux/arm64/v8"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "linux/arm64 and linux/arm64/v8 are the same platform")
			},
		},
		{
			name: "failure duplicate platforms with the default arm variant",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "linux/arm/v7,linux/arm"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "linux/arm/v7 and linux/arm are the same platform")
			},
		},
		{
			name: "failure different platforms with the same layer name",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "linux/arm/v7,linux/arm:v7"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				require.ErrorContains(t, err, "both name the layer profile-linux-arm-v7")
			},
		},
		{
			name: "failure parse platforms",
			prepare: func(t *testing.T, set *flag.FlagSet) {
				t.Helper()

				require.NoError(t, set.Parse([]string{"echo"}))
				set.Var(ucli.NewStringSlice(""), FlagPlatforms, "")
				require.NoError(t, set.Set(FlagPlatforms, "this/is/a/wrong/platform"))
			},
			assert: func(t *testing.T, _ *Options, err error) {
				t.Helper()

				assert.Error(t, err)
			},
		},
	} {
		testPrepare := tc.prepare
		testAssert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ExitOnError)
			testPrepare(t, set)

			app := ucli.NewApp()
			ctx := ucli.NewContext(app, set, nil)

			options, err := FromContext(ctx)
			testAssert(t, options, err)
		})
	}
}

// TestAnnotationsFlag asserts that a comma only separates annotations if the
// text after it starts with a key and a colon, so that values may contain
// commas.
//
//nolint:paralleltest // App.Run sets the global HelpFlag of urfave/cli
func TestAnnotationsFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want map[string]string
	}{
		{
			name: "comma in a value",
			args: []string{"-a", "org.opencontainers.image.description:A profile, for nginx"},
			want: map[string]string{"org.opencontainers.image.description": "A profile, for nginx"},
		},
		{
			name: "several annotations in one value",
			args: []string{"-a", "k1:v1,k2:v2"},
			want: map[string]string{"k1": "v1", "k2": "v2"},
		},
		{
			name: "repeated flag",
			args: []string{"-a", "k1:a,b", "-a", "k2: v2 "},
			want: map[string]string{"k1": "a,b", "k2": "v2"},
		},
		{
			name: "colon after a comma in a value",
			args: []string{"-a", "description:A profile, see https://example.com"},
			want: map[string]string{"description": "A profile, see https://example.com"},
		},
		{
			name: "URL after a comma in a value",
			args: []string{"-a", "description:A profile, https://example.com"},
			want: map[string]string{"description": "A profile, https://example.com"},
		},
		{
			name: "times after a comma in a value",
			args: []string{"-a", "time:10:00, 11:00"},
			want: map[string]string{"time": "10:00, 11:00"},
		},
		{
			name: "space after a comma between annotations",
			args: []string{"-a", "k1:v1, k2:v2"},
			want: map[string]string{"k1": "v1", "k2": "v2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got map[string]string

			app := &ucli.App{
				Flags: Flags(),
				Action: func(ctx *ucli.Context) error {
					options, err := FromContext(ctx)
					if err != nil {
						return err
					}

					got = options.annotations

					return nil
				},
			}

			args := append([]string{"spoc"}, tc.args...)
			require.NoError(t, app.Run(append(args, "registry/image:tag")))
			require.Equal(t, tc.want, got)
		})
	}
}

// TestAnnotationsFlagOccurrences asserts that every occurrence of the flag
// needs a key, a comma cannot join it to the one before.
//
//nolint:paralleltest // App.Run sets the global HelpFlag of urfave/cli
func TestAnnotationsFlagOccurrences(t *testing.T) {
	app := &ucli.App{
		Flags: Flags(),
		Action: func(ctx *ucli.Context) error {
			_, err := FromContext(ctx)

			return err
		},
	}

	err := app.Run([]string{"spoc", "-a", "k:v", "-a", "typo", "registry/image:tag"})
	require.ErrorContains(t, err, "wrong annotation format: typo")

	// A trailing comma fails like for the released versions.
	err = app.Run([]string{"spoc", "-a", "k:v,", "registry/image:tag"})
	require.ErrorContains(t, err, "wrong annotation format")
}
