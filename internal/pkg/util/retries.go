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
	"fmt"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	backoffDuration = 500 * time.Millisecond
	backoffFactor   = 1.5
	backoffSteps    = 5
	backoffJitter   = 0.1
)

func IsNotFoundOrConflict(err error) bool {
	return kerrors.IsNotFound(err) || kerrors.IsConflict(err)
}

// DefaultBackoff returns the retry backoff used by RetryWithContext.
// The jitter keeps many clients, like the daemons of all nodes, from retrying
// a conflict in lockstep.
func DefaultBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
		Jitter:   backoffJitter,
	}
}

// RetryWithContext runs fn with the DefaultBackoff until it succeeds or fails
// with an error which does not meet retryCondition. It stops waiting between
// the attempts once the context is done.
func RetryWithContext(
	ctx context.Context, fn func() error, retryCondition func(error) bool,
) error {
	return RetryWithBackoff(ctx, DefaultBackoff(), fn, retryCondition)
}

// RetryWithFreshReads is like RetryWithContext for a fn which reads and writes
// an object through the client it gets. The first attempt gets c, which
// usually reads from the cache. The later ones read through the reader,
// usually the API reader of the manager, because the cache may keep returning
// the version of the object which made the attempt fail. Without a reader,
// every attempt gets c.
func RetryWithFreshReads(
	ctx context.Context,
	c client.Client,
	reader client.Reader,
	fn func(client.Client) error,
	retryCondition func(error) bool,
) error {
	attemptClient := c

	return RetryWithContext(ctx, func() error {
		err := fn(attemptClient)
		if reader != nil {
			attemptClient = &freshReadClient{Client: c, reader: reader}
		}

		return err
	}, retryCondition)
}

// freshReadClient is a client which reads objects through the reader.
type freshReadClient struct {
	client.Client

	reader client.Reader
}

func (c *freshReadClient) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	return c.reader.Get(ctx, key, obj, opts...)
}

// RetryWithBackoff is like RetryWithContext with the provided backoff.
func RetryWithBackoff(
	ctx context.Context,
	backoff wait.Backoff,
	fn func() error,
	retryCondition func(error) bool,
) error {
	r := &retrier{fn: fn, retryCondition: retryCondition}

	return r.result(wait.ExponentialBackoffWithContext(
		ctx, backoff, func(context.Context) (bool, error) { return r.attempt() },
	))
}

// retryFatalError marks an error which retryCondition did not accept.
type retryFatalError struct{ err error }

func (e *retryFatalError) Error() string { return e.err.Error() }

func (e *retryFatalError) Unwrap() error { return e.err }

// retrier runs fn until it succeeds or fails with an error which does not
// meet retryCondition.
type retrier struct {
	fn             func() error
	retryCondition func(error) bool

	// lastRetryErr is the last error which got retried.
	lastRetryErr error
}

// attempt runs fn once. A failure which meets retryCondition is kept and
// retried, any other one ends the retries.
func (r *retrier) attempt() (bool, error) {
	err := r.fn()
	if err == nil {
		return true, nil
	} else if r.retryCondition(err) {
		r.lastRetryErr = err

		return false, nil
	}

	return false, &retryFatalError{err: err}
}

// result wraps the result of the backoff once: a failure which was not
// retried is returned as the error of fn, an interrupted wait along with the
// last error of fn.
func (r *retrier) result(waitErr error) error {
	if waitErr == nil {
		return nil
	}

	if fatal, ok := errors.AsType[*retryFatalError](waitErr); ok {
		return fmt.Errorf("retry function: %w", fatal.err)
	}

	if r.lastRetryErr != nil && wait.Interrupted(waitErr) {
		return fmt.Errorf("wait on retry: %w, last retry error: %w", waitErr, r.lastRetryErr)
	}

	return fmt.Errorf("wait on retry: %w", waitErr)
}
