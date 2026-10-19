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
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// envSignalContextChild makes the test binary act as the process which gets
// the signals in TestSignalContextSecondSignal.
const envSignalContextChild = "SPOC_TEST_SIGNAL_CONTEXT_CHILD"

// TestSignalContextSecondSignal verifies that the first signal cancels the
// context and a second one terminates the process, even if nothing stops on
// the context.
func TestSignalContextSecondSignal(t *testing.T) {
	t.Parallel()

	if os.Getenv(envSignalContextChild) == "second" {
		os.Exit(signalContextChild())
	}

	//nolint:gosec // the test binary itself
	cmd := exec.CommandContext(
		t.Context(), os.Args[0], "-test.run=^TestSignalContextSecondSignal$",
	)

	cmd.Env = append(os.Environ(), envSignalContextChild+"=second")

	out, err := cmd.CombinedOutput()

	exitErr := &exec.ExitError{}
	require.ErrorAs(t, err, &exitErr, "output: %s", out)

	status, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled(), "output: %s", out)
	require.Equal(t, syscall.SIGINT, status.Signal())
	require.Contains(t, string(out), "context canceled")
}

// signalContextChild signals itself until it gets terminated and returns
// the exit code otherwise. The first signal only cancels the context, which
// it reports.
func signalContextChild() int {
	ctx, stop := SignalContext()
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		return 1
	}

	<-ctx.Done()

	if errors.Is(ctx.Err(), context.Canceled) {
		os.Stderr.WriteString("context canceled\n")
	}

	// The default handling gets restored right after the cancellation.
	for range 500 {
		if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
			return 1
		}

		time.Sleep(10 * time.Millisecond)
	}

	return 0
}

// TestSignalContextDuplicateSignal verifies that a signal which arrives twice
// at once, directly and forwarded by a parent, does not terminate the process.
func TestSignalContextDuplicateSignal(t *testing.T) {
	t.Parallel()

	if os.Getenv(envSignalContextChild) == "duplicate" {
		os.Exit(signalContextDuplicateChild())
	}

	//nolint:gosec // the test binary itself
	cmd := exec.CommandContext(
		t.Context(), os.Args[0], "-test.run=^TestSignalContextDuplicateSignal$",
	)

	cmd.Env = append(os.Environ(), envSignalContextChild+"=duplicate")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	require.Contains(t, string(out), "context canceled")
}

// signalContextDuplicateChild signals itself twice at once and returns zero
// if it still runs afterwards.
func signalContextDuplicateChild() int {
	ctx, stop := SignalContext()
	defer stop()

	for range 2 {
		if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
			return 1
		}
	}

	<-ctx.Done()

	// The duplicate may arrive after the cancellation.
	time.Sleep(DuplicateSignalWindow / 4)

	if errors.Is(ctx.Err(), context.Canceled) {
		os.Stderr.WriteString("context canceled\n")
	}

	return 0
}
