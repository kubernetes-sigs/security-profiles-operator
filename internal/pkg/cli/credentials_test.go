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
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	ucli "github.com/urfave/cli/v2"
)

func TestRegistryCredentials(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		args          []string
		env           map[string]string
		stdin         string
		wantUser      string
		wantPassword  string
		wantErr       error
		wantErrSubstr string
	}{
		{name: "anonymous"},
		{
			name:         "flag and environment",
			args:         []string{"--username", "user"},
			env:          map[string]string{EnvKeyPassword: "pass"},
			wantUser:     "user",
			wantPassword: "pass",
		},
		{
			name:         "environment only",
			env:          map[string]string{EnvKeyUsername: "user", EnvKeyPassword: "pass"},
			wantUser:     "user",
			wantPassword: "pass",
		},
		{
			name:         "flag wins over environment",
			args:         []string{"--username", "flag"},
			env:          map[string]string{EnvKeyUsername: "env", EnvKeyPassword: "pass"},
			wantUser:     "flag",
			wantPassword: "pass",
		},
		{
			name:         "password from stdin",
			args:         []string{"--username", "user", "--password-stdin"},
			stdin:        "secret\n",
			wantUser:     "user",
			wantPassword: "secret",
		},
		{
			name:    "password from stdin and environment",
			args:    []string{"--username", "user", "--password-stdin"},
			env:     map[string]string{EnvKeyPassword: "pass"},
			stdin:   "secret",
			wantErr: ErrConflictingPasswords,
		},
		{
			name:         "deprecated environment",
			env:          map[string]string{EnvKeyUsernameDeprecated: "user", EnvKeyPasswordDeprecated: "pass"},
			wantUser:     "user",
			wantPassword: "pass",
		},
		{
			name:         "deprecated password with new username",
			env:          map[string]string{EnvKeyUsername: "user", EnvKeyPasswordDeprecated: "pass"},
			wantUser:     "user",
			wantPassword: "pass",
		},
		{
			name: "deprecated username alone is the login name",
			env:  map[string]string{EnvKeyUsernameDeprecated: "login"},
		},
		{
			name:          "username without password",
			args:          []string{"--username", "user"},
			env:           map[string]string{EnvKeyUsernameDeprecated: "login"},
			wantErr:       ErrIncompleteCredentials,
			wantErrSubstr: "no password",
		},
		{
			name:          "password without username",
			env:           map[string]string{EnvKeyPassword: "pass"},
			wantErr:       ErrIncompleteCredentials,
			wantErrSubstr: "no username",
		},
		{
			name:          "empty password from stdin",
			args:          []string{"--username", "user", "--password-stdin"},
			stdin:         "\n",
			wantErr:       ErrIncompleteCredentials,
			wantErrSubstr: "no password",
		},
		{
			name:          "empty password from stdin ignores deprecated environment",
			args:          []string{"--username", "user", "--password-stdin"},
			env:           map[string]string{EnvKeyPasswordDeprecated: "pass"},
			stdin:         "\n",
			wantErr:       ErrIncompleteCredentials,
			wantErrSubstr: "no password",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			set := flag.NewFlagSet("", flag.ContinueOnError)
			set.String(FlagUsername, "", "")
			set.Bool(FlagPasswordStdin, false, "")
			require.NoError(t, set.Parse(tc.args))

			ctx := ucli.NewContext(ucli.NewApp(), set, nil)
			getenv := func(key string) string { return tc.env[key] }

			user, password, err := RegistryCredentials(ctx, strings.NewReader(tc.stdin), getenv)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorContains(t, err, tc.wantErrSubstr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantUser, user)
			require.Equal(t, tc.wantPassword, password)
		})
	}
}
