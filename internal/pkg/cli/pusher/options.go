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
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// Options define all possible options for the pusher.
type Options struct {
	pushTo         string
	inputFiles     map[*v1.Platform]string
	username       string
	password       string
	annotations    map[string]string
	disableSigning bool

	disableArtifactValidation bool
	plainHTTP                 bool
	oidcDeviceFlow            bool
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		inputFiles: map[*v1.Platform]string{},
	}
}

// Flags returns the flags of the push command.
func Flags() []ucli.Flag {
	flags := []ucli.Flag{
		&ucli.StringSliceFlag{
			Name:        FlagProfiles,
			Aliases:     []string{"f", flagProfileAlias},
			Usage:       "the profiles to be used (profile CRD YAML or raw runtime-spec seccomp JSON)",
			DefaultText: DefaultInputFile,
			TakesFile:   true,
		},
		&ucli.GenericFlag{
			Name:    FlagAnnotations,
			Aliases: []string{"a"},
			Usage: "the annotations to be set in `KEY:VALUE` format, separated by commas " +
				"or by repeating the flag; a value with a comma followed by a word and a " +
				"colon needs a flag of its own",
			Value: &annotationsFlag{},
		},
		&ucli.BoolFlag{
			Name:    FlagDisableSigning,
			Aliases: []string{"s"},
			Usage: "do not sign the artifact after pushing it, " +
				"for environments without an OIDC identity",
		},
		&ucli.BoolFlag{
			Name: FlagDisableArtifactValidation,
			Usage: "push a runtime-spec seccomp profile even if " +
				"container runtimes would reject it as a KEP-6061 " +
				"artifact, for publishing test fixtures",
		},
		&ucli.StringSliceFlag{
			Name:    FlagPlatforms,
			Aliases: []string{"p", flagPlatformAlias},
			Usage: "the platforms to be used in format: os[/arch][/variant][:os_version], " +
				"one per profile; without platforms, the single profile is platform independent " +
				"and gets pulled on every platform",
		},
	}

	flags = append(flags, cli.RegistryFlags()...)

	return append(flags, cli.SigningFlags()...)
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *ucli.Context) (*Options, error) {
	options := Default()

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no remote location provided")
	}

	options.pushTo = args[0]
	cli.WarnExtraArgs(args, 1)

	inputFiles, err := inputFiles(ctx.StringSlice(FlagProfiles), ctx.StringSlice(FlagPlatforms))
	if err != nil {
		return nil, err
	}

	options.inputFiles = inputFiles

	username, password, err := cli.RegistryCredentials(ctx, os.Stdin, os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("get registry credentials: %w", err)
	}

	options.username = username
	options.password = password
	options.disableSigning = ctx.Bool(FlagDisableSigning)
	options.disableArtifactValidation = ctx.Bool(FlagDisableArtifactValidation)
	options.plainHTTP = ctx.Bool(FlagPlainHTTP)
	options.oidcDeviceFlow = ctx.Bool(FlagOIDCDeviceFlow)

	var values []string
	if flag, ok := ctx.Generic(FlagAnnotations).(*annotationsFlag); ok {
		values = flag.values
	}

	options.annotations, err = annotations(values)
	if err != nil {
		return nil, err
	}

	return options, nil
}

// inputFiles returns the profiles to push by platform. Without platforms,
// the single profile is platform independent, so that it can be pulled on
// every platform.
func inputFiles(profiles, platforms []string) (map[*v1.Platform]string, error) {
	files := map[*v1.Platform]string{}

	if len(platforms) == 0 {
		if len(profiles) > 1 {
			return nil, errors.New("multiple profiles provided but no platforms set")
		}

		profile := DefaultInputFile
		if len(profiles) == 1 {
			profile = profiles[0]
		}

		files[nil] = profile

		return files, nil
	}

	parsedPlatforms := []*v1.Platform{}

	// Every platform gets its own layer, named after it. Spellings like
	// "linux" and "linux/amd64" on an amd64 host parse to the same platform,
	// and "linux/arm/v7" and "linux/arm:v7" give the same layer name.
	layers := map[string]string{}

	for _, platform := range platforms {
		parsedPlatform, err := cli.ParsePlatform(platform)
		if err != nil {
			return nil, fmt.Errorf("parse platform %s: %w", platform, err)
		}

		layer := artifact.ProfileName(parsedPlatform)
		if other, ok := layers[layer]; ok {
			return nil, fmt.Errorf(
				"duplicate platforms defined: %s and %s both name the layer %s",
				other, platform, layer,
			)
		}

		// Platforms which differ in the default variant only, like
		// "linux/arm64" and "linux/arm64/v8", are the same one on pull,
		// which would then pick one of their profiles.
		for j, other := range parsedPlatforms {
			if artifact.SamePlatform(other, parsedPlatform) {
				return nil, fmt.Errorf(
					"duplicate platforms defined: %s and %s are the same platform",
					platforms[j], platform,
				)
			}
		}

		layers[layer] = platform

		parsedPlatforms = append(parsedPlatforms, parsedPlatform)
	}

	switch {
	case len(profiles) == 0 && len(platforms) > 1:
		return nil, fmt.Errorf(
			"%d platforms provided but no profiles, use one --%s per --%s",
			len(platforms), FlagProfiles, FlagPlatforms,
		)
	case len(profiles) == 0:
		files[parsedPlatforms[0]] = DefaultInputFile
	case len(profiles) != len(platforms):
		return nil, errors.New("number of profiles and platforms do not match")
	}

	for i, profile := range profiles {
		files[parsedPlatforms[i]] = profile
	}

	return files, nil
}

// annotationStart matches the start of a comma separated part of an
// annotations flag which starts another annotation: a key and a colon.
var annotationStart = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._/-]*:`)

// annotationsFlag is the value of the annotations flag. Every occurrence of
// the flag is one annotation, or several separated by commas. A comma only
// separates annotations if a key and a colon follow it, which are not the
// scheme of a URL, so that "description:A profile, https://example.com" and
// "time:10:00, 11:00" stay one annotation, while "k1:v1,k2:v2" and
// "k1:v1, k2:v2" set two. A value containing a comma followed by a word and a
// colon needs a flag of its own.
type annotationsFlag struct {
	values []string
}

func (a *annotationsFlag) Set(value string) error {
	parts := strings.Split(value, ",")
	a.values = append(a.values, parts[0])

	for _, part := range parts[1:] {
		trimmed := strings.TrimSpace(part)

		// An empty part fails like for the released versions.
		if trimmed == "" || startsAnnotation(trimmed) {
			a.values = append(a.values, trimmed)

			continue
		}

		a.values[len(a.values)-1] += "," + part
	}

	return nil
}

// startsAnnotation reports whether a comma separated part of an annotations
// flag starts with a key and a colon, which are not the scheme of a URL.
func startsAnnotation(part string) bool {
	key := annotationStart.FindString(part)

	return key != "" && !strings.HasPrefix(part[len(key):], "//")
}

func (a *annotationsFlag) String() string {
	return strings.Join(a.values, ",")
}

// annotations parses the annotations in KEY:VALUE format. Only the first
// colon separates key and value, so that values such as RFC 3339 timestamps
// keep their own colons.
func annotations(values []string) (map[string]string, error) {
	const parts = 2

	result := map[string]string{}

	for _, a := range values {
		split := strings.SplitN(a, ":", parts)
		if len(split) < parts {
			return nil, fmt.Errorf("wrong annotation format: %s", a)
		}

		key := strings.TrimSpace(split[0])
		if key == "" {
			return nil, fmt.Errorf("empty annotation key: %s", a)
		}

		result[key] = strings.TrimSpace(split[1])
	}

	return result, nil
}
