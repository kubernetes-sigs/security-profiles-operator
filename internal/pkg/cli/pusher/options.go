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
	"errors"
	"fmt"
	"os"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	ucli "github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// Options define all possible options for the pusher.
type Options struct {
	pushTo      string
	inputFiles  map[*v1.Platform]string
	username    string
	password    string
	annotations map[string]string
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		inputFiles: map[*v1.Platform]string{},
	}
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *ucli.Context) (*Options, error) {
	options := Default()

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no remote location provided")
	}

	options.pushTo = args[0]

	profiles := ctx.StringSlice(FlagProfiles)
	platforms := ctx.StringSlice(FlagPlatforms)

	if len(platforms) == 0 {
		if len(profiles) > 1 {
			return nil, errors.New("multiple profiles provided but no platforms set")
		} else if len(profiles) == 1 {
			options.inputFiles[DefaultPlatform] = profiles[0]
		}
	} else {
		// Avoid duplicate platforms because they have to be unique in the map.
		if sets.New(platforms...).Len() != len(platforms) {
			return nil, fmt.Errorf(
				"duplicate platforms defined: %v", strings.Join(platforms, ", "),
			)
		}

		parsedPlatforms := []*v1.Platform{}

		for _, platform := range platforms {
			parsedPlatform, err := cli.ParsePlatform(platform)
			if err != nil {
				return nil, fmt.Errorf("parse platform %s: %w", platform, err)
			}

			parsedPlatforms = append(parsedPlatforms, parsedPlatform)
		}

		if len(profiles) == 0 {
			options.inputFiles[parsedPlatforms[0]] = DefaultInputFile
		} else if len(profiles) != len(platforms) {
			return nil, errors.New("number of profiles and platforms do not match")
		}

		for i, profile := range profiles {
			options.inputFiles[parsedPlatforms[i]] = profile
		}
	}

	if ctx.IsSet(FlagUsername) {
		options.username = ctx.String(FlagUsername)
	}

	options.password = os.Getenv(cli.EnvKeyPassword)
	options.annotations = map[string]string{}

	for _, a := range ctx.StringSlice(FlagAnnotations) {
		split := strings.Split(a, ":")

		const minparts = 2

		if len(split) < minparts {
			return nil, fmt.Errorf("wrong annotation format: %s", a)
		}

		key := strings.TrimSpace(split[0])
		value := strings.TrimSpace(split[1])
		options.annotations[key] = value
	}

	return options, nil
}
