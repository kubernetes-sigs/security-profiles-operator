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

package recorder

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
)

// Options define all possible options for the recorder.
type Options struct {
	typ          Type
	outputFile   string
	baseSyscalls []string
	command      string
	args         []string
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		typ:          TypeSeccomp,
		outputFile:   DefaultOutputFile,
		baseSyscalls: DefaultBaseSyscalls,
	}
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *cli.Context) (*Options, error) {
	options := Default()

	if ctx.IsSet(FlagOutputFile) {
		options.outputFile = ctx.String(FlagOutputFile)
	}
	if options.outputFile == "" {
		return nil, errors.New("no filename provided")
	}

	if ctx.IsSet(FlagType) {
		options.typ = Type(ctx.String(FlagType))
	}
	if options.typ != TypeSeccomp && options.typ != TypeRawSeccomp {
		return nil, fmt.Errorf("unsupported %s: %s", FlagType, options.typ)
	}

	if ctx.IsSet(FlagBaseSyscalls) {
		options.baseSyscalls = ctx.StringSlice(FlagBaseSyscalls)
	}
	if ctx.IsSet(FlagNoBaseSyscalls) {
		options.baseSyscalls = nil
	}

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no command provided")
	}
	options.command = args[0]
	options.args = args[1:]

	return options, nil
}
