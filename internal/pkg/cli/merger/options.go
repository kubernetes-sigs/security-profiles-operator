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
	"errors"

	ucli "github.com/urfave/cli/v2"
)

// Options define all possible options for the puller.
type Options struct {
	inputFiles []string
	outputFile string
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
		return nil, errors.New("no profiles provided")
	}
	options.inputFiles = args

	if ctx.IsSet(FlagOutputFile) {
		options.outputFile = ctx.String(FlagOutputFile)
	}
	if options.outputFile == "" {
		return nil, errors.New("no filename provided")
	}

	return options, nil
}
