//go:build linux && !no_bpf

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

package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// runTest exercises spoc run: the command has to be confined by the profile
// every time, run as the user who invoked sudo and pass its exit code on.
func runTest(t *testing.T) {
	const profile = `{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [{"names": ["mkdir", "mkdirat"], "action": "SCMP_ACT_ERRNO"}]
}
`

	in := writeTempFile(t, "profile.json", profile)

	// The command runs as the test user, who owns the directory.
	dir := t.TempDir()

	t.Run("command is confined", func(t *testing.T) {
		for i := range 10 {
			target := filepath.Join(dir, fmt.Sprintf("confined-%d", i))

			_, err := runSpoc(t, "run", "-p", in, "mkdir", target)
			requireExitCode(t, err, 1)
			require.NoDirExists(t, target, "run %d escaped the profile", i)
		}
	})

	t.Run("exit code is passed on", func(t *testing.T) {
		_, err := runSpoc(t, "run", "-p", in, "sh", "-c", "exit 7")
		requireExitCode(t, err, 7)
	})

	t.Run("command runs as the invoking user", func(t *testing.T) {
		_, err := runSpoc(t,
			"run", "-p", in, "sh", "-c", `test "$(id -u)" = "`+strconv.Itoa(os.Getuid())+`"`,
		)
		require.NoError(t, err)
	})
}

// requireExitCode asserts that spoc exited with the code.
func requireExitCode(t *testing.T, err error, code int) {
	t.Helper()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, code, exitErr.ExitCode())
}
