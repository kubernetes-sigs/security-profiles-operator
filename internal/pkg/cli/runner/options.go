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

package runner

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
)

// Options define all possible options for the runner.
type Options struct {
	commandOptions *command.Options
	typ            Type
	profile        string
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		commandOptions: command.Default(),
		typ:            TypeSeccomp,
		profile:        DefaultInputFile,
	}
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *cli.Context) (*Options, error) {
	options := Default()

	if ctx.IsSet(FlagProfile) {
		options.profile = ctx.String(FlagProfile)
	}
	if options.profile == "" {
		return nil, errors.New("no profile provided")
	}

	if ctx.IsSet(FlagType) {
		options.typ = Type(ctx.String(FlagType))
	}
	if options.typ != TypeSeccomp {
		return nil, fmt.Errorf("unsupported %s: %s", FlagType, options.typ)
	}

	commandOptions, err := command.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("get command options: %w", err)
	}
	options.commandOptions = commandOptions

	return options, nil
}
