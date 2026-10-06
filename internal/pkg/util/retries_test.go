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

package util

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
)

// testBackoff returns a backoff which does not slow the tests down.
func testBackoff() *wait.Backoff {
	return &wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 3}
}

func TestRetryEx(t *testing.T) {
	t.Parallel()

	errRetryable := errors.New("retryable")
	errFatal := errors.New("fatal")
	isRetryable := func(err error) bool { return errors.Is(err, errRetryable) }

	t.Run("succeeds on the first attempt", func(t *testing.T) {
		t.Parallel()

		calls := 0

		require.NoError(t, RetryEx(testBackoff(), func() error {
			calls++

			return nil
		}, isRetryable))
		require.Equal(t, 1, calls)
	})

	t.Run("retries a retryable error until it succeeds", func(t *testing.T) {
		t.Parallel()

		calls := 0

		require.NoError(t, RetryEx(testBackoff(), func() error {
			calls++
			if calls < 3 {
				return errRetryable
			}

			return nil
		}, isRetryable))
		require.Equal(t, 3, calls)
	})

	t.Run("returns another error right away", func(t *testing.T) {
		t.Parallel()

		calls := 0

		err := RetryEx(testBackoff(), func() error {
			calls++

			return errFatal
		}, isRetryable)
		require.ErrorIs(t, err, errFatal)
		// The error is wrapped once.
		require.Equal(t, "retry function: fatal", err.Error())
		require.Equal(t, 1, calls)
	})

	t.Run("gives up after the steps and keeps the last error", func(t *testing.T) {
		t.Parallel()

		calls := 0

		err := RetryEx(testBackoff(), func() error {
			calls++

			return errRetryable
		}, isRetryable)
		require.ErrorIs(t, err, errRetryable)
		require.ErrorContains(t, err, "wait on retry")
		require.True(t, wait.Interrupted(err))
		require.Equal(t, 3, calls)
	})
}

func TestRetryWithContext(t *testing.T) {
	t.Parallel()

	t.Run("retries a conflict", func(t *testing.T) {
		t.Parallel()

		calls := 0

		require.NoError(t, RetryWithContext(t.Context(), func() error {
			calls++
			if calls == 1 {
				return kerrors.NewConflict(schema.GroupResource{}, "name", nil)
			}

			return nil
		}, IsNotFoundOrConflict))
		require.Equal(t, 2, calls)
	})

	t.Run("returns another error once wrapped", func(t *testing.T) {
		t.Parallel()

		err := RetryWithContext(t.Context(), func() error {
			return errors.New("fatal")
		}, IsNotFoundOrConflict)
		require.Equal(t, "retry function: fatal", err.Error())
	})

	t.Run("stops once the context is done", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())
		calls := 0

		err := RetryWithContext(ctx, func() error {
			calls++

			cancel()

			return kerrors.NewConflict(schema.GroupResource{}, "name", nil)
		}, IsNotFoundOrConflict)
		require.ErrorIs(t, err, context.Canceled)
		require.True(t, kerrors.IsConflict(err))
		require.Equal(t, 1, calls)
	})
}

func TestRetry(t *testing.T) {
	t.Parallel()

	calls := 0

	require.NoError(t, Retry(func() error {
		calls++
		if calls == 1 {
			return kerrors.NewConflict(schema.GroupResource{}, "name", nil)
		}

		return nil
	}, IsNotFoundOrConflict))
	require.Equal(t, 2, calls)
}

func TestIsNotFoundOrConflict(t *testing.T) {
	t.Parallel()

	require.True(t, IsNotFoundOrConflict(kerrors.NewNotFound(schema.GroupResource{}, "name")))
	require.True(t, IsNotFoundOrConflict(kerrors.NewConflict(schema.GroupResource{}, "name", nil)))
	require.False(t, IsNotFoundOrConflict(kerrors.NewBadRequest("bad")))
	require.False(t, IsNotFoundOrConflict(errors.New("other")))
	require.False(t, IsNotFoundOrConflict(nil))
}

func TestDefaultBackoff(t *testing.T) {
	t.Parallel()

	backoff := DefaultBackoff()
	require.Equal(t, backoffDuration, backoff.Duration)
	require.InDelta(t, backoffFactor, backoff.Factor, 0)
	require.Equal(t, backoffSteps, backoff.Steps)
	require.InDelta(t, backoffJitter, backoff.Jitter, 0)
}
