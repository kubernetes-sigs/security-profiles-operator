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
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
)

const (
	// DefaultSenderQueueSize is the number of requests a Sender buffers while
	// the metrics server is slow or unreachable.
	DefaultSenderQueueSize = 1024

	minReconnectDelay = 100 * time.Millisecond
	maxReconnectDelay = 30 * time.Second
)

// Stream is the part of a gRPC client stream a Sender uses.
type Stream[T any] interface {
	Send(T) error
}

// OpenContextFunc opens a new stream to the metrics server, bound to ctx. The
// returned function releases the stream and its connection.
type OpenContextFunc[T any] func(ctx context.Context) (Stream[T], func(), error)

// Sender delivers requests to the local metrics server from a background
// goroutine.
//
// Sending never blocks the caller: requests are queued and dropped once the
// queue is full, so a slow or restarting metrics server cannot stall the audit
// log or BPF event processing. A stream which fails is re-opened with backoff
// before the next request is delivered, because a gRPC client stream stays
// broken once the server side went away.
type Sender[T any] struct {
	logger logr.Logger
	open   OpenContextFunc[T]
	queue  chan T

	mu      sync.Mutex
	stream  Stream[T]
	release func()
	// dropped counts the requests which did not fit into the queue. It is
	// not guarded by mu, which is held while a stream is opened.
	dropped atomic.Uint64

	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration)
}

// NewContextSender returns a new Sender which opens streams with open, bound
// to the context of ConnectContext or Run. It does not open a stream until one
// of them is called.
func NewContextSender[T any](
	logger logr.Logger,
	queueSize int,
	open OpenContextFunc[T],
) *Sender[T] {
	return &Sender[T]{
		logger: logger,
		open:   open,
		queue:  make(chan T, queueSize),
		sleep:  sleepContext,
	}
}

// ConnectContext opens the initial stream, bound to ctx. It lets callers fail
// fast if the metrics server is not reachable at all on startup.
func (s *Sender[T]) ConnectContext(ctx context.Context) error {
	stream, release, err := s.open(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeLocked()
	s.stream, s.release = stream, release

	return nil
}

// Send queues req for delivery. It reports false if the queue was full and the
// request was dropped.
func (s *Sender[T]) Send(req T) bool {
	select {
	case s.queue <- req:
		return true
	default:
		dropped := s.dropped.Add(1)

		// Only log every so often, a full queue drops a lot.
		if dropped == 1 || dropped%DefaultSenderQueueSize == 0 {
			s.logger.Info("Dropping metrics because the queue is full", "dropped", dropped)
		}

		return false
	}
}

// Run delivers the queued requests until ctx is done.
func (s *Sender[T]) Run(ctx context.Context) {
	defer s.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case req := <-s.queue:
			s.deliver(ctx, req)
		}
	}
}

// Close releases the current stream.
func (s *Sender[T]) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeLocked()
}

func (s *Sender[T]) closeLocked() {
	if s.release != nil {
		s.release()
	}

	s.stream, s.release = nil, nil
}

// deliver sends req, re-opening the stream as often as needed. It only gives
// up when ctx is done.
func (s *Sender[T]) deliver(ctx context.Context, req T) {
	delay := minReconnectDelay

	for ctx.Err() == nil {
		stream, err := s.currentStream(ctx)
		if err == nil {
			if err = stream.Send(req); err == nil {
				return
			}

			s.Close()
		}

		s.logger.Error(err, "Unable to send metrics, reconnecting", "delay", delay)
		s.sleep(ctx, delay)

		delay = min(2*delay, maxReconnectDelay)
	}
}

func (s *Sender[T]) currentStream(ctx context.Context) (Stream[T], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stream != nil {
		return s.stream, nil
	}

	stream, release, err := s.open(ctx)
	if err != nil {
		return nil, err
	}

	s.stream, s.release = stream, release

	return stream, nil
}

func sleepContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
