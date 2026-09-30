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

package metrics

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
)

var errSend = errors.New("send failed")

type fakeStream struct {
	mu       sync.Mutex
	fail     bool
	received []int
}

func (f *fakeStream) Send(req int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.fail {
		return errSend
	}

	f.received = append(f.received, req)

	return nil
}

func (f *fakeStream) got() []int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]int(nil), f.received...)
}

func TestSenderReopensBrokenStream(t *testing.T) {
	t.Parallel()

	broken := &fakeStream{fail: true}
	healthy := &fakeStream{}

	var (
		mu       sync.Mutex
		opened   int
		released int
	)

	sut := NewContextSender(logr.Discard(), 10, func(context.Context) (Stream[int], func(), error) {
		mu.Lock()
		defer mu.Unlock()

		opened++

		release := func() {
			mu.Lock()
			released++
			mu.Unlock()
		}

		// The first stream is the one of a metrics server which restarted.
		if opened == 1 {
			return broken, release, nil
		}

		return healthy, release, nil
	})
	sut.sleep = func(context.Context, time.Duration) {}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	require.NoError(t, sut.ConnectContext(ctx))

	go sut.Run(ctx)

	require.True(t, sut.Send(1))
	require.True(t, sut.Send(2))

	require.Eventually(t, func() bool {
		return len(healthy.got()) == 2
	}, time.Minute, time.Millisecond)

	require.Equal(t, []int{1, 2}, healthy.got())

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, 2, opened)
	require.Equal(t, 1, released)
}

func TestSenderRetriesUntilOpenSucceeds(t *testing.T) {
	t.Parallel()

	stream := &fakeStream{}

	var (
		mu       sync.Mutex
		attempts int
	)

	sut := NewContextSender(logr.Discard(), 10, func(context.Context) (Stream[int], func(), error) {
		mu.Lock()
		defer mu.Unlock()

		attempts++
		if attempts < 3 {
			return nil, nil, errSend
		}

		return stream, func() {}, nil
	})
	sut.sleep = func(context.Context, time.Duration) {}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go sut.Run(ctx)

	require.True(t, sut.Send(42))

	require.Eventually(t, func() bool {
		return len(stream.got()) == 1
	}, time.Minute, time.Millisecond)
}

func TestSenderNeverBlocks(t *testing.T) {
	t.Parallel()

	sut := NewContextSender(logr.Discard(), 1, func(context.Context) (Stream[int], func(), error) {
		return &fakeStream{}, func() {}, nil
	})

	// Nothing drains the queue, so the second request has to be dropped
	// instead of blocking the caller.
	require.True(t, sut.Send(1))
	require.False(t, sut.Send(2))
	require.EqualValues(t, 1, sut.dropped.Load())
}

// TestSenderDropsWhileOpening asserts that a stream which takes long to open
// does not block the callers, whose requests are counted as dropped.
func TestSenderDropsWhileOpening(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	opening := make(chan struct{})

	sut := NewContextSender(logr.Discard(), 1, func(context.Context) (Stream[int], func(), error) {
		close(opening)
		<-release

		return &fakeStream{}, func() {}, nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go sut.Run(ctx)

	require.True(t, sut.Send(1))
	<-opening

	// The first request is being delivered while the stream is opened, the
	// second one fills the queue.
	require.True(t, sut.Send(2))
	require.False(t, sut.Send(3))
	require.EqualValues(t, 1, sut.dropped.Load())

	close(release)
}

func TestSenderConnectFails(t *testing.T) {
	t.Parallel()

	sut := NewContextSender(logr.Discard(), 1, func(context.Context) (Stream[int], func(), error) {
		return nil, nil, errSend
	})

	require.ErrorIs(t, sut.ConnectContext(t.Context()), errSend)
}

// TestSenderBindsStreamsToContext asserts that the streams are opened with
// the context of the sender, so that stopping it releases them.
func TestSenderBindsStreamsToContext(t *testing.T) {
	t.Parallel()

	type key struct{}

	var (
		mu       sync.Mutex
		contexts []context.Context
	)

	sut := NewContextSender(
		logr.Discard(),
		10,
		func(ctx context.Context) (Stream[int], func(), error) {
			mu.Lock()
			defer mu.Unlock()

			contexts = append(contexts, ctx)

			return &fakeStream{}, func() {}, nil
		},
	)

	connectCtx := context.WithValue(t.Context(), key{}, "connect")
	require.NoError(t, sut.ConnectContext(connectCtx))

	// Closing the stream makes Run open another one, with its own context.
	sut.Close()

	runCtx, cancel := context.WithCancel(context.WithValue(t.Context(), key{}, "run"))
	defer cancel()

	go sut.Run(runCtx)

	require.True(t, sut.Send(1))

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		return len(contexts) == 2
	}, time.Minute, time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, "connect", contexts[0].Value(key{}))
	require.Equal(t, "run", contexts[1].Value(key{}))
}
