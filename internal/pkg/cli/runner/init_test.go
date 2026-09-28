//go:build linux

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

package runner

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
)

// TestMain lets the test binary act as run helper, like spoc does.
func TestMain(m *testing.M) {
	Init()
	os.Exit(m.Run())
}

// runConfined runs the command through the run helper with the profile and
// returns the error of its exit.
func runConfined(t *testing.T, profile *specs.LinuxSeccomp, args ...string) error {
	t.Helper()

	set := flag.NewFlagSet("", flag.ContinueOnError)
	require.NoError(t, set.Parse(args))

	options, err := command.FromContext(cli.NewContext(cli.NewApp(), set, nil))
	require.NoError(t, err)

	options.DropSudoPrivileges = false
	options.PreStart = confine(profile)

	cmd := command.New(options)
	_, err = cmd.Run()
	require.NoError(t, err)

	return cmd.Wait()
}

// TestConfine verifies that every command started through the run helper is
// confined, no matter which thread of spoc starts it, and that spoc itself is
// not.
func TestConfine(t *testing.T) {
	t.Parallel()

	if !seccomp.Enabled {
		t.Skip("built without seccomp support")
	}

	for _, name := range []string{"mkdir", "true"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s not available: %v", name, err)
		}
	}

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{"mkdir", "mkdirat"},
			Action: specs.ActErrno,
		}},
	}

	if code, exited := command.ExitCode(runConfined(t, profile, "true")); exited {
		require.NotEqual(t, initFailedExitCode, code, "run helper failed")
		require.FailNow(t, "true failed", "exit code %d", code)
	}

	const runs = 20

	dir := t.TempDir()
	confinedErrs := make([]error, runs)
	spocErrs := make([]error, runs)

	var wg sync.WaitGroup

	for i := range runs {
		wg.Go(func() {
			target := filepath.Join(dir, fmt.Sprintf("confined-%d", i))
			confinedErrs[i] = runConfined(t, profile, "mkdir", target)

			// spoc must stay unconfined on every thread.
			spocErrs[i] = os.Mkdir(filepath.Join(dir, fmt.Sprintf("spoc-%d", i)), 0o700)
		})
	}

	wg.Wait()

	for i := range runs {
		require.ErrorContains(t, confinedErrs[i], "exit status 1", "run %d", i)
		require.NoDirExists(t, filepath.Join(dir, fmt.Sprintf("confined-%d", i)))
		require.NoError(t, spocErrs[i], "run %d", i)
	}
}

// TestConfineUnknownCommand verifies that a command which does not exist
// fails to start instead of starting the run helper.
func TestConfineUnknownCommand(t *testing.T) {
	t.Parallel()

	set := flag.NewFlagSet("", flag.ContinueOnError)
	require.NoError(t, set.Parse([]string{"spoc-does-not-exist"}))

	options, err := command.FromContext(cli.NewContext(cli.NewApp(), set, nil))
	require.NoError(t, err)

	options.PreStart = confine(&specs.LinuxSeccomp{DefaultAction: specs.ActAllow})

	_, err = command.New(options).Run()
	require.ErrorIs(t, err, exec.ErrNotFound)
}
