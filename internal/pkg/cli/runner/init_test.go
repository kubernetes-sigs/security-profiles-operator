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
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"

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

// TestConfineKillsNothingButTheCommand verifies that nothing but the
// execution of the command is subject to the profile, so that a profile which
// kills on a syscall the command does not make lets it run.
//
//nolint:paralleltest // lowers the file limit of the test process
func TestConfineKillsNothingButTheCommand(t *testing.T) {
	if !seccomp.Enabled {
		t.Skip("built without seccomp support")
	}

	if _, err := exec.LookPath("true"); err != nil {
		t.Skipf("true not available: %v", err)
	}

	// The run helper only raises a soft limit below the hard one, which it
	// then sets back before executing the command.
	var limit syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit))

	if limit.Max < 4 {
		t.Skipf("hard file limit %d too low", limit.Max)
	}

	lowered := limit
	lowered.Cur = limit.Max / 2
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered))

	t.Cleanup(func() {
		require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit))
	})

	// Go sets the file limit through prlimit64 before executing a command,
	// the dynamic loader only reads the stack limit.
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActAllow,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{"prlimit64"},
			Action: specs.ActKillProcess,
			Args: []specs.LinuxSeccompArg{{
				Index: 1,
				Value: unix.RLIMIT_NOFILE,
				Op:    specs.OpEqualTo,
			}},
		}},
	}

	require.NoError(t, runConfined(t, profile, "true"))
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

// TestConfinePassesCredential verifies that the credential of a command run
// under sudo is passed to the run helper, which drops the privileges after
// loading the profile, instead of starting the helper unprivileged.
func TestConfinePassesCredential(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 1000, Gid: 1001, Groups: []uint32{1001, 27}},
	}
	path := cmd.Path

	postStart, err := confine(&specs.LinuxSeccomp{DefaultAction: specs.ActAllow})(cmd)
	require.NoError(t, err)

	defer postStart()

	require.Nil(
		t,
		cmd.SysProcAttr.Credential,
		"the run helper needs the privileges to load the profile",
	)
	require.Equal(t, selfExe, cmd.Path)
	require.Equal(t, []string{os.Args[0], InitArg}, cmd.Args)
	require.Len(t, cmd.ExtraFiles, 1)

	config := &initConfig{}
	require.NoError(t, json.NewDecoder(cmd.ExtraFiles[0]).Decode(config))
	require.Equal(
		t,
		&initCredential{UID: 1000, GID: 1001, Groups: []uint32{1001, 27}},
		config.Credential,
	)
	require.Equal(t, path, config.Path)
	require.Equal(t, []string{"true"}, config.Args)
}
