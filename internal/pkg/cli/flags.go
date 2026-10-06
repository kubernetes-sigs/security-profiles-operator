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

package cli

import (
	"fmt"

	ucli "github.com/urfave/cli/v2"
)

// FlagOIDCDeviceFlow is the flag for signing in to the OIDC provider with the
// device flow if there is no terminal.
const FlagOIDCDeviceFlow string = "oidc-device-flow"

// RegistryFlags returns the flags for the registry access shared by the
// commands which push, pull or sign: the username and password of the
// registry authentication and HTTP instead of HTTPS.
func RegistryFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.StringFlag{
			Name:    FlagUsername,
			Aliases: []string{"u"},
			Usage: fmt.Sprintf(
				"the username for registry authentication (default: $%s), "+
					"the password is read from $%s or with --%s from stdin; "+
					"without both, the docker config credentials are used; "+
					"$%s and $%s are deprecated and still used with a warning",
				EnvKeyUsername, EnvKeyPassword, FlagPasswordStdin,
				EnvKeyUsernameDeprecated, EnvKeyPasswordDeprecated,
			),
		},
		&ucli.BoolFlag{
			Name:  FlagPasswordStdin,
			Usage: "read the password for registry authentication from stdin",
		},
		&ucli.BoolFlag{
			Name:  FlagPlainHTTP,
			Usage: "use HTTP instead of HTTPS to reach the registry, for local registries in tests",
		},
	}
}

// SigningFlags returns the flags for keyless signing shared by the commands
// which sign.
func SigningFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.BoolFlag{
			Name: FlagOIDCDeviceFlow,
			Usage: "sign in to the OIDC provider with the device flow if the environment " +
				"has no identity token and stdin is not a terminal, instead of failing",
		},
	}
}
