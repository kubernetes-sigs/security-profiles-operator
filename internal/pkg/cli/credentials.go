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
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	ucli "github.com/urfave/cli/v2"
)

// maxPasswordSize is the longest password accepted from stdin for --password-stdin.
const maxPasswordSize = 64 << 10

var (
	// ErrIncompleteCredentials is returned if only a username or only a
	// password is given for registry authentication.
	ErrIncompleteCredentials = errors.New(
		"registry authentication needs both a username and a password",
	)

	// ErrConflictingPasswords is returned if the password is given via stdin
	// and the environment at the same time.
	ErrConflictingPasswords = errors.New("password given via stdin and environment")

	// ErrPasswordTooLong is returned if the password given via stdin does not
	// fit into maxPasswordSize.
	ErrPasswordTooLong = errors.New("password given via stdin is too long")
)

// RegistryCredentials returns the username and password for the registry
// authentication. The username is taken from the flag or $SPOC_USERNAME, the
// password from stdin if requested or $SPOC_PASSWORD. The former $USERNAME
// and $PASSWORD are still used with a warning, $USERNAME only together with
// a password because it commonly holds the login name. Only one of both being
// set is an error, the registry access would silently be anonymous otherwise.
// Without any, the registry access falls back to the credentials of the docker
// config.
func RegistryCredentials(
	ctx *ucli.Context, stdin io.Reader, getenv func(string) string,
) (username, password string, err error) {
	username = ctx.String(FlagUsername)
	if username == "" {
		username = getenv(EnvKeyUsername)
	}

	password = getenv(EnvKeyPassword)

	if ctx.Bool(FlagPasswordStdin) {
		if password != "" {
			return "", "", fmt.Errorf(
				"%w: --%s and $%s", ErrConflictingPasswords, FlagPasswordStdin, EnvKeyPassword,
			)
		}

		// Reading beyond the limit and its line break tells a password which
		// does not fit, which must not be cut off.
		const lineBreak = 2 // "\r\n"

		content, err := io.ReadAll(io.LimitReader(stdin, maxPasswordSize+lineBreak+1))
		if err != nil {
			return "", "", fmt.Errorf("read password from stdin: %w", err)
		}

		password = strings.TrimRight(string(content), "\r\n")
		if len(password) > maxPasswordSize || len(content) > maxPasswordSize+lineBreak {
			return "", "", fmt.Errorf("%w: more than %d bytes", ErrPasswordTooLong, maxPasswordSize)
		}
	}

	// A password requested from stdin must not be replaced by the one of the
	// environment if stdin is empty.
	if password == "" && !ctx.Bool(FlagPasswordStdin) {
		if password = getenv(EnvKeyPasswordDeprecated); password != "" {
			log.Printf("WARNING: $%s is deprecated, use $%s or --%s instead",
				EnvKeyPasswordDeprecated, EnvKeyPassword, FlagPasswordStdin)
		}
	}

	if username == "" && password != "" {
		if username = getenv(EnvKeyUsernameDeprecated); username != "" {
			log.Printf("WARNING: $%s is deprecated, use $%s or --%s instead",
				EnvKeyUsernameDeprecated, EnvKeyUsername, FlagUsername)
		}
	}

	switch {
	case username != "" && password == "":
		return "", "", fmt.Errorf(
			"%w: got username %q but no password, set $%s or use --%s",
			ErrIncompleteCredentials, username, EnvKeyPassword, FlagPasswordStdin,
		)
	case username == "" && password != "":
		return "", "", fmt.Errorf(
			"%w: got a password but no username, set --%s or $%s",
			ErrIncompleteCredentials, FlagUsername, EnvKeyUsername,
		)
	}

	return username, password, nil
}
