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

package artifact

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAwaitContext(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test")

	value, err := AwaitContext(t.Context(), func() (string, error) {
		return "value", errTest
	})
	require.ErrorIs(t, err, errTest)
	require.Equal(t, "value", value)

	ctx, cancel := context.WithCancel(t.Context())
	release := make(chan struct{})
	started := make(chan struct{})

	t.Cleanup(func() { close(release) })

	go func() {
		<-started
		cancel()
	}()

	// A function which ignores the context does not keep the caller
	// waiting once the context ends.
	value, err = AwaitContext(ctx, func() (string, error) {
		close(started)
		<-release

		return "late", nil
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, value)

	// A context which ended already does not start the function.
	_, err = AwaitContext(ctx, func() (string, error) {
		require.Fail(t, "the function must not run")

		return "", nil
	})
	require.ErrorIs(t, err, context.Canceled)
}

// TestAwaitContextPanic asserts that a panic of the function, which runs in a
// goroutine of its own, becomes an error instead of ending the process.
func TestAwaitContextPanic(t *testing.T) {
	t.Parallel()

	_, err := AwaitContext(t.Context(), func() (string, error) {
		panic("broken refresh")
	})
	require.ErrorIs(t, err, errPanic)
	require.ErrorContains(t, err, "broken refresh")
	require.ErrorContains(t, err, "goroutine", "the stack of the panic is kept")
}
