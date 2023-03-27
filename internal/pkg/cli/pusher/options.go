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

	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// Options define all possible options for the pusher.
type Options struct {
	pushTo      string
	inputFile   string
	username    string
	password    string
	annotations map[string]string
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{
		inputFile: DefaultInputFile,
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

	if ctx.IsSet(FlagProfile) {
		options.inputFile = ctx.String(FlagProfile)
	}
	if options.inputFile == "" {
		return nil, errors.New("no profile provided")
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
