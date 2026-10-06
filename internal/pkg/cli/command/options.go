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

package command

import (
	"errors"
	"os/exec"

	"github.com/urfave/cli/v2"
)

// Options define all possible options for the command.
type Options struct {
	command            string
	args               []string
	DropSudoPrivileges bool

	// PreStart is called with the prepared command right before it gets
	// started and may change it, for example to start it through a helper.
	// The returned function, if not nil, is called after the start attempt.
	PreStart func(*exec.Cmd) (postStart func(), err error)
}

// Command returns the command name.
func (o *Options) Command() string {
	return o.command
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		DropSudoPrivileges: true,
	}
}

// Flags returns the flags of the commands which run a command.
func Flags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:  FlagPrivileged,
			Usage: "do not drop sudo privileges when running the target command",
		},
	}
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

	if ctx.Bool(FlagPrivileged) {
		options.DropSudoPrivileges = false
	}

	return options, nil
}
