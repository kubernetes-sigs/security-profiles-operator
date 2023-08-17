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
	"errors"
	"fmt"
	"os"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// Options define all possible options for the puller.
type Options struct {
	pullFrom                     string
	outputFile                   string
	username                     string
	password                     string
	platform                     *v1.Platform
	disableSignatureVerification bool
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		outputFile: DefaultOutputFile,
	}
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *ucli.Context) (*Options, error) {
	options := Default()

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no remote image provided")
	}
	options.pullFrom = args[0]

	if ctx.IsSet(FlagOutputFile) {
		options.outputFile = ctx.String(FlagOutputFile)
	}
	if options.outputFile == "" {
		return nil, errors.New("no filename provided")
	}

	if ctx.IsSet(FlagUsername) {
		options.username = ctx.String(FlagUsername)
	}

	if ctx.IsSet(FlagDisableSignatureVerification) {
		options.disableSignatureVerification = ctx.Bool(FlagDisableSignatureVerification)
	}

	options.password = os.Getenv(cli.EnvKeyPassword)

	platform, err := cli.ParsePlatform(ctx.String(FlagPlatform))
	if err != nil {
		return nil, fmt.Errorf("parse platform: %w", err)
	}
	options.platform = platform

	return options, nil
}
