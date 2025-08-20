package buffer

import (
	"errors"
	"fmt"
	"time"
)

const (
	invalidSize     = "size cannot be zero"
	invalidFlusher  = "flusher cannot be nil"
	invalidInterval = "interval must be greater than zero (%s)"
	invalidTimeout  = "timeout cannot be negative (%s)"
)

type (
	// Configuration options.
	Options struct {
		Size          uint
		Flusher       Flusher
		FlushInterval time.Duration
		PushTimeout   time.Duration
		FlushTimeout  time.Duration
		CloseTimeout  time.Duration
	}

	// Option setter.
	Option func(*Options)
)

// WithSize sets the size of the buffer.
func WithSize(size uint) Option {
	return func(options *Options) {
		options.Size = size
	}
}

// WithFlusher sets the flusher that should be used to write out the buffer.
func WithFlusher(flusher Flusher) Option {
	return func(options *Options) {
		options.Flusher = flusher
	}
}

// WithFlushInterval sets the interval between automatic flushes.
func WithFlushInterval(interval time.Duration) Option {
	return func(options *Options) {
		options.FlushInterval = interval
	}
}

// WithPushTimeout sets how long a push should wait before giving up.
func WithPushTimeout(timeout time.Duration) Option {
	return func(options *Options) {
		options.PushTimeout = timeout
	}
}

// WithFlushTimeout sets how long a manual flush should wait before giving up.
func WithFlushTimeout(timeout time.Duration) Option {
	return func(options *Options) {
		options.FlushTimeout = timeout
	}
}

// WithCloseTimeout sets how long
func WithCloseTimeout(timeout time.Duration) Option {
	return func(options *Options) {
		options.CloseTimeout = timeout
	}
}

func validateOptions(options *Options) error {
	if options.Size == 0 {
		return errors.New(invalidSize)
	}
	if options.Flusher == nil {
		return errors.New(invalidFlusher)
	}
	if options.FlushInterval < 0 {
		return fmt.Errorf(invalidInterval, "FlushInterval")
	}
	if options.PushTimeout < 0 {
		return fmt.Errorf(invalidTimeout, "PushTimeout")
	}
	if options.FlushTimeout < 0 {
		return fmt.Errorf(invalidTimeout, "FlushTimeout")
	}
	if options.CloseTimeout < 0 {
		return fmt.Errorf(invalidTimeout, "CloseTimeout")
	}

	return nil
}

func resolveOptions(opts ...Option) *Options {
	options := &Options{
		Size:          0,
		Flusher:       nil,
		FlushInterval: 0,
		PushTimeout:   time.Second,
		FlushTimeout:  time.Second,
		CloseTimeout:  time.Second,
	}

	for _, opt := range opts {
		opt(options)
	}

	if err := validateOptions(options); err != nil {
		panic(err)
	}

	return options
}
