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
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
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

// marshalStream marshals the requests like a gRPC client stream, which fails
// for invalid UTF-8 in a string field.
type marshalStream struct {
	mu       sync.Mutex
	received []*api.AuditRequest
}

func (m *marshalStream) Send(req *api.AuditRequest) error {
	if _, err := proto.Marshal(req); err != nil {
		return status.Errorf(codes.Internal, "grpc: error while marshaling: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.received = append(m.received, req)

	return nil
}

func (m *marshalStream) got() []*api.AuditRequest {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]*api.AuditRequest(nil), m.received...)
}

// TestSenderSanitizesInvalidUTF8 asserts that a request with invalid UTF-8,
// which cannot be marshalled, gets delivered with the invalid bytes replaced
// without failing a send.
func TestSenderSanitizesInvalidUTF8(t *testing.T) {
	t.Parallel()

	stream := &marshalStream{}

	var (
		mu     sync.Mutex
		opened int
	)

	sut := NewContextSender(logr.Discard(), 10,
		func(context.Context) (Stream[*api.AuditRequest], func(), error) {
			mu.Lock()
			defer mu.Unlock()

			opened++

			return stream, func() {}, nil
		})
	sut.sleep = func(context.Context, time.Duration) {
		t.Error("a request error must not back off")
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go sut.Run(ctx)

	req := &api.AuditRequest{
		Node:       "node",
		Pod:        "pod\xff",
		SeccompReq: &api.AuditRequest_SeccompAuditReq{Syscall: "read\xfe"},
	}
	require.True(t, sut.Send(req))

	require.Eventually(t, func() bool {
		return len(stream.got()) == 1
	}, time.Minute, time.Millisecond)

	got := stream.got()[0]
	require.Equal(t, "node", got.GetNode())
	require.Equal(t, "pod\uFFFD", got.GetPod())
	require.Equal(t, "read\uFFFD", got.GetSeccompReq().GetSyscall())

	// The queued request stays untouched.
	require.Equal(t, "pod\xff", req.GetPod())
	require.Zero(t, sut.rejected.Load())

	mu.Lock()
	defer mu.Unlock()

	// The request is sanitized before sending it, a failed send would finish
	// the stream with the requests which are still buffered.
	require.Equal(t, 1, opened)
}

// TestSenderDropsRequestWhichCannotBeSent asserts that a request which fails
// on its own is dropped instead of being retried forever, and that the next
// one gets delivered.
func TestSenderDropsRequestWhichCannotBeSent(t *testing.T) {
	t.Parallel()

	for _, code := range []codes.Code{codes.Internal, codes.ResourceExhausted} {
		t.Run(code.String(), func(t *testing.T) {
			t.Parallel()

			stream := &rejectingStream{reject: 1, code: code}

			sut := NewContextSender(logr.Discard(), 10,
				func(context.Context) (Stream[int], func(), error) {
					return stream, func() {}, nil
				})
			sut.sleep = func(context.Context, time.Duration) {
				t.Error("a request error must not back off")
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			go sut.Run(ctx)

			require.True(t, sut.Send(1))
			require.True(t, sut.Send(2))

			require.Eventually(t, func() bool {
				return len(stream.got()) == 1
			}, time.Minute, time.Millisecond)

			require.Equal(t, []int{2}, stream.got())
			require.EqualValues(t, 1, sut.rejected.Load())
			require.Equal(t, 1, stream.attempts(1))
		})
	}
}

// TestSenderDropsOversizedRequest asserts that a request above the message
// size limit of the server is dropped before sending it. The server resets
// the stream on such a request, which makes Send fail with io.EOF like a
// broken transport and would make the sender retry it forever.
func TestSenderDropsOversizedRequest(t *testing.T) {
	t.Parallel()

	stream := &marshalStream{}

	var (
		mu     sync.Mutex
		opened int
	)

	sut := NewContextSender(logr.Discard(), 10,
		func(context.Context) (Stream[*api.AuditRequest], func(), error) {
			mu.Lock()
			defer mu.Unlock()

			opened++

			return stream, func() {}, nil
		})
	sut.sleep = func(context.Context, time.Duration) {
		t.Error("an oversized request must not back off")
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go sut.Run(ctx)

	oversized := &api.AuditRequest{Pod: strings.Repeat("a", MaxMsgSize)}
	require.Greater(t, proto.Size(oversized), MaxMsgSize)

	require.True(t, sut.Send(oversized))
	require.True(t, sut.Send(&api.AuditRequest{Pod: "pod"}))

	require.Eventually(t, func() bool {
		return len(stream.got()) == 1
	}, time.Minute, time.Millisecond)

	require.Equal(t, "pod", stream.got()[0].GetPod())
	require.EqualValues(t, 1, sut.rejected.Load())

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, 1, opened)
}

// rejectingStream fails every request equal to reject with code.
type rejectingStream struct {
	fakeStream

	reject int
	code   codes.Code

	attemptsMu sync.Mutex
	tried      map[int]int
}

func (r *rejectingStream) Send(req int) error {
	r.attemptsMu.Lock()

	if r.tried == nil {
		r.tried = map[int]int{}
	}

	r.tried[req]++
	r.attemptsMu.Unlock()

	if req == r.reject {
		return status.Error(r.code, "request error")
	}

	return r.fakeStream.Send(req)
}

func (r *rejectingStream) attempts(req int) int {
	r.attemptsMu.Lock()
	defer r.attemptsMu.Unlock()

	return r.tried[req]
}

func TestRequestError(t *testing.T) {
	t.Parallel()

	require.True(t, requestError(status.Error(codes.Internal, "marshal")))
	require.True(t, requestError(status.Error(codes.ResourceExhausted, "too large")))
	require.False(t, requestError(io.EOF))
	require.False(t, requestError(errSend))
	require.False(t, requestError(status.Error(codes.Unavailable, "gone")))
}

func TestSanitizeUTF8(t *testing.T) {
	t.Parallel()

	valid := &api.AuditRequest{
		Node:       "node",
		SeccompReq: &api.AuditRequest_SeccompAuditReq{Syscall: "read"},
	}

	got, ok := sanitizeUTF8(valid)
	require.False(t, ok)
	require.Same(t, valid, got, "a valid request is not copied")

	invalid := &api.AuditRequest{
		Node:       "node",
		SeccompReq: &api.AuditRequest_SeccompAuditReq{Syscall: "read\xfe"},
	}

	got, ok = sanitizeUTF8(invalid)
	require.True(t, ok)
	require.Equal(t, "read\uFFFD", got.GetSeccompReq().GetSyscall())
	require.Equal(t, "read\xfe", invalid.GetSeccompReq().GetSyscall())

	_, ok = sanitizeUTF8(1)
	require.False(t, ok, "no protobuf message")
}
