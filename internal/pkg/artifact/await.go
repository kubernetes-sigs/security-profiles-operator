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
	"fmt"
	"runtime/debug"
)

// errPanic is returned by AwaitContext if its function panics.
var errPanic = errors.New("panic")

// AwaitContext runs fn, which does not stop on the context, like the TUF
// client or an interactive sign in, and returns the error of the context if
// it ends first, for example on the first interrupt of spoc. fn keeps running
// in the background then until it returns on its own, bounded by its own
// timeouts, and its result gets dropped.
func AwaitContext[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	if ctx.Err() != nil {
		var zero T

		return zero, context.Cause(ctx)
	}

	type result struct {
		value T
		err   error
	}

	done := make(chan result, 1)

	// fn used to run in the goroutine of its caller, like a reconcile which
	// recovers from panics. A panic of fn must not end the process now.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("%w: %v\n%s", errPanic, r, debug.Stack())}
			}
		}()

		value, err := fn()
		done <- result{value: value, err: err}
	}()

	select {
	case res := <-done:
		return res.value, res.err
	case <-ctx.Done():
		var zero T

		return zero, context.Cause(ctx)
	}
}
