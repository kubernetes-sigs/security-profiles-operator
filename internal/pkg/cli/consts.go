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

const (
	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = "output-file"

	// FlagUsername is the flag for defining the username for registry
	// authentication.
	FlagUsername string = "username"

	// FlagPasswordStdin is the flag for reading the password for registry
	// authentication from stdin.
	FlagPasswordStdin string = "password-stdin"

	// FlagPlainHTTP is the flag for talking to the registry over HTTP.
	FlagPlainHTTP string = "plain-http"

	// EnvKeyUsername is the environment variable key for defining the
	// username for registry authentication if the flag is not set.
	EnvKeyUsername string = "SPOC_USERNAME"

	// EnvKeyPassword is the environment variable key for defining the password
	// for registry authentication.
	EnvKeyPassword string = "SPOC_PASSWORD"

	// EnvKeyUsernameDeprecated is the former environment variable key for the
	// username, still used with a warning in favor of EnvKeyUsername. It is
	// only used together with a password, because it commonly holds the login
	// name.
	EnvKeyUsernameDeprecated string = "USERNAME"

	// EnvKeyPasswordDeprecated is the former environment variable key for the
	// password, still used with a warning in favor of EnvKeyPassword.
	EnvKeyPasswordDeprecated string = "PASSWORD"

	// FilePermissions are the permissions of the profiles spoc writes. They
	// contain no secrets.
	FilePermissions = 0o644

	// FlagOIDCDeviceFlow is the flag for signing in to the OIDC provider with
	// the device flow if there is no terminal.
	FlagOIDCDeviceFlow string = "oidc-device-flow"
)

// DefaultFile defines the default input and output location for profiles. It
// is relative to the working directory, a fixed path in the shared temporary
// directory could be prepared by other users.
var DefaultFile = "profile.yaml"
