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

package signer

import (
	"errors"
	"fmt"
	"os"

	ucli "github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// Options define all possible options for the signer.
type Options struct {
	image          string
	username       string
	password       string
	plainHTTP      bool
	oidcDeviceFlow bool
}

// Default returns a default options instance.
func Default() *Options {
	return &Options{}
}

// Flags returns the flags of the sign command, the registry and signing
// flags of the push command.
func Flags() []ucli.Flag {
	return append(cli.RegistryFlags(), cli.SigningFlags()...)
}

// FromContext can be used to create Options from an CLI context.
func FromContext(ctx *ucli.Context) (*Options, error) {
	options := Default()

	args := ctx.Args().Slice()
	if len(args) == 0 {
		return nil, errors.New("no image provided")
	}

	if len(args) > 1 {
		return nil, errors.New("too many arguments, sign one image at a time")
	}

	options.image = args[0]

	username, password, err := cli.RegistryCredentials(ctx, os.Stdin, os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("get registry credentials: %w", err)
	}

	options.username = username
	options.password = password
	options.plainHTTP = ctx.Bool(FlagPlainHTTP)
	options.oidcDeviceFlow = ctx.Bool(FlagOIDCDeviceFlow)

	return options, nil
}
