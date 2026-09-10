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

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

// TestCommandFlagNamesAreUnique guards against a duplicate flag name or alias
// within a command, which urfave/cli only reports by panicking when the
// command runs.
func TestCommandFlagNamesAreUnique(t *testing.T) {
	t.Parallel()

	var assertCommand func(t *testing.T, command *cli.Command)

	assertCommand = func(t *testing.T, command *cli.Command) {
		t.Helper()

		seen := map[string]bool{}

		for _, flag := range command.Flags {
			for _, name := range flag.Names() {
				require.False(
					t, seen[name],
					"flag %q defined more than once for command %q", name, command.Name,
				)

				seen[name] = true
			}
		}

		for _, subCommand := range command.Subcommands {
			assertCommand(t, subCommand)
		}
	}

	for _, command := range newApp().Commands {
		assertCommand(t, command)
	}
}
