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

package recorder

import (
	"errors"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
)

// Options define all possible options for the recorder.
type Options struct {
	commandOptions *command.Options
	typ            Type
	outputFile     string
	baseSyscalls   []string
	noProcStart    bool
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		commandOptions: command.Default(),
		typ:            TypeSeccomp,
		outputFile:     DefaultOutputFile,
		baseSyscalls:   DefaultBaseSyscalls,
		noProcStart:    false,
	}
}

// Flags returns the flags of the record command.
func Flags() []cli.Flag {
	return append([]cli.Flag{
		&cli.StringFlag{
			Name:        FlagOutputFile,
			Aliases:     []string{"o"},
			Usage:       "the output file path for the recorded profile",
			DefaultText: DefaultOutputFile,
			TakesFile:   true,
		},
		&cli.StringFlag{
			Name:    FlagType,
			Aliases: []string{"t"},
			Usage: fmt.Sprintf(
				"the record type: %s, %s, %s, %s or %s",
				TypeSeccomp, TypeRawSeccomp, TypeApparmor, TypeRawAppArmor, TypeAll,
			),
			DefaultText: string(TypeSeccomp),
		},
		&cli.StringSliceFlag{
			Name:    FlagBaseSyscalls,
			Aliases: []string{"b"},
			Usage: "base syscalls to be included in every profile " +
				"to ensure compatibility with OCI runtimes like runc and crun",
			DefaultText: strings.Join(DefaultBaseSyscalls, ", "),
		},
		&cli.BoolFlag{
			Name:    FlagNoBaseSyscalls,
			Aliases: []string{"n"},
			Usage:   "do not add any base syscalls at all",
		},
		&cli.BoolFlag{
			Name: FlagNoProcStart,
			Usage: "do not start the target command, record all processes matching the command name " +
				"until ctrl+c/SIGINT, SIGTERM or SIGHUP",
		},
	}, command.Flags()...)
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

	if options.typ != TypeSeccomp && options.typ != TypeRawSeccomp &&
		options.typ != TypeApparmor && options.typ != TypeRawAppArmor && options.typ != TypeAll {
		return nil, fmt.Errorf("unsupported %s: %s", FlagType, options.typ)
	}

	if ctx.IsSet(FlagBaseSyscalls) {
		options.baseSyscalls = ctx.StringSlice(FlagBaseSyscalls)
	}

	if ctx.Bool(FlagNoBaseSyscalls) {
		options.baseSyscalls = nil
	}

	options.noProcStart = ctx.Bool(FlagNoProcStart)

	commandOptions, err := command.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("get command options: %w", err)
	}

	options.commandOptions = commandOptions

	return options, nil
}
