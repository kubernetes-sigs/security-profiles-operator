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
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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
// broken once the server side went away. A request which cannot be sent at
// all, like one which cannot be marshalled, is dropped instead of being
// retried forever. So is a protobuf request which exceeds the message size
// limit of the metrics server, which would otherwise reset the stream.
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
	// rejected counts the requests which got dropped because sending them
	// failed for the request itself.
	rejected atomic.Uint64

	// maxSize is the size limit of a protobuf request, replaced in tests.
	maxSize int
	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration)
}

// errTooLarge is the reason for dropping a request which exceeds maxSize.
var errTooLarge = errors.New("request exceeds the message size limit")

// NewContextSender returns a new Sender which opens streams with open, bound
// to the context of ConnectContext or Run. It does not open a stream until one
// of them is called.
func NewContextSender[T any](
	logger logr.Logger,
	queueSize int,
	open OpenContextFunc[T],
) *Sender[T] {
	return &Sender[T]{
		logger:  logger,
		open:    open,
		queue:   make(chan T, queueSize),
		maxSize: MaxMsgSize,
		sleep:   sleepContext,
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
// up when ctx is done or when req itself cannot be sent.
func (s *Sender[T]) deliver(ctx context.Context, req T) {
	delay := minReconnectDelay

	// Invalid UTF-8 in a string field is the usual reason why a request
	// cannot be marshalled. gRPC finishes the stream on such a request,
	// which drops the requests sent before it that are still buffered, so
	// it gets replaced before sending.
	if fixed, ok := sanitizeUTF8(req); ok {
		req = fixed
	}

	for ctx.Err() == nil {
		// The server resets the stream on a request above its limit, which
		// makes Send fail with io.EOF like a broken transport.
		if s.tooLarge(req) {
			s.reject(errTooLarge)

			return
		}

		stream, err := s.currentStream(ctx)
		if err == nil {
			if err = stream.Send(req); err == nil {
				return
			}

			// gRPC finishes a client stream on every error of Send.
			s.Close()

			if requestError(err) {
				s.reject(err)

				return
			}
		}

		s.logger.Error(err, "Unable to send metrics, reconnecting", "delay", delay)
		s.sleep(ctx, delay)

		delay = min(2*delay, maxReconnectDelay)
	}
}

// reject drops a request which cannot be sent.
func (s *Sender[T]) reject(err error) {
	rejected := s.rejected.Add(1)

	// Only log every so often, a sender of broken requests rejects a lot.
	if rejected == 1 || rejected%DefaultSenderQueueSize == 0 {
		s.logger.Error(err, "Dropping metrics which cannot be sent", "rejected", rejected)
	}
}

// tooLarge reports whether req is a protobuf message which exceeds maxSize.
func (s *Sender[T]) tooLarge(req T) bool {
	msg, ok := any(req).(proto.Message)

	return ok && proto.Size(msg) > s.maxSize
}

// requestError reports whether a Send failed for the request itself rather
// than for the stream: gRPC returns Internal for a request which cannot be
// marshalled and ResourceExhausted for one which is too large. Sending the
// same request again fails the same way. A broken transport makes Send
// return io.EOF instead.
func requestError(err error) bool {
	code := status.Code(err)

	return code == codes.Internal || code == codes.ResourceExhausted
}

// sanitizeUTF8 returns a copy of a protobuf request with the invalid UTF-8 of
// its string fields replaced, which proto3 refuses to marshal. It reports
// false if req is no protobuf message or has nothing to replace.
func sanitizeUTF8[T any](req T) (T, bool) {
	msg, ok := any(req).(proto.Message)
	if !ok {
		return req, false
	}

	// Most requests are valid, which are not copied.
	if validUTF8Message(msg.ProtoReflect()) {
		return req, false
	}

	msg = proto.Clone(msg)
	if !sanitizeMessage(msg.ProtoReflect()) {
		return req, false
	}

	fixed, ok := msg.(T)

	return fixed, ok
}

// validUTF8Message reports whether the string fields of msg and of its nested
// messages are valid UTF-8.
func validUTF8Message(msg protoreflect.Message) bool {
	valid := true

	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			// The metrics API has no maps.
		case fd.IsList():
			list := v.List()

			for i := range list.Len() {
				valid = valid && validUTF8Value(fd, list.Get(i))
			}
		default:
			valid = validUTF8Value(fd, v)
		}

		return valid
	})

	return valid
}

// validUTF8Value reports whether the value of a field is valid UTF-8, see
// validUTF8Message.
func validUTF8Value(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
	switch {
	case fd.Kind() == protoreflect.StringKind:
		return utf8.ValidString(v.String())
	case fd.Message() != nil:
		return validUTF8Message(v.Message())
	default:
		return true
	}
}

// sanitizeMessage replaces the invalid UTF-8 in the string fields of msg and
// of its nested messages. It reports whether it changed anything.
func sanitizeMessage(msg protoreflect.Message) bool {
	changed := false
	fixed := map[protoreflect.FieldDescriptor]protoreflect.Value{}

	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			// The metrics API has no maps.
		case fd.IsList():
			list := v.List()

			for i := range list.Len() {
				if value, ok := sanitizeValue(fd, list.Get(i)); ok {
					list.Set(i, value)

					changed = true
				}
			}
		default:
			if value, ok := sanitizeValue(fd, v); ok {
				fixed[fd] = value
			}
		}

		return true
	})

	// Setting the fields while ranging over them is not allowed.
	for fd, value := range fixed {
		msg.Set(fd, value)
	}

	return changed || len(fixed) > 0
}

// sanitizeValue returns the sanitized string value of a field, and reports
// whether it differs. A nested message gets sanitized in place.
func sanitizeValue(
	fd protoreflect.FieldDescriptor, v protoreflect.Value,
) (protoreflect.Value, bool) {
	if fd.Kind() == protoreflect.StringKind {
		if s := v.String(); !utf8.ValidString(s) {
			return protoreflect.ValueOfString(strings.ToValidUTF8(s, string(utf8.RuneError))), true
		}

		return v, false
	}

	if fd.Message() != nil {
		return v, sanitizeMessage(v.Message())
	}

	return v, false
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
