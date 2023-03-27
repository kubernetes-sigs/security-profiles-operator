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

package command

import (
	"errors"

	"github.com/urfave/cli/v2"
)

// Options define all possible options for the command.
type Options struct {
	command string
	args    []string
}

// Command returns the command name.
func (o *Options) Command() string {
	return o.command
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{}
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *cli.Context) (*Options, error) {
	options := Default()

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no command provided")
	}
	options.command = args[0]
	options.args = args[1:]

	return options, nil
}
