package roko

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

var defaultRandom = rand.New(rand.NewSource(time.Now().UnixNano()))

const jitterInterval = 1000 * time.Millisecond

type Retrier struct {
	maxAttempts  int
	attemptCount int
	jitter       bool
	forever      bool
	rand         *rand.Rand

	breakNext bool
	sleepFunc func(time.Duration)

	intervalCalculator Strategy
	strategyType       string
	manualInterval     *time.Duration
}

type Strategy func(*Retrier) time.Duration

const (
	constantStrategy    = "constant"
	exponentialStrategy = "exponential"
)

// Constant returns a strategy that always returns the same value, the interval passed in as an arg to the function
// Semantically, when this is used with a roko.Retrier, it means that the retrier will always wait the given
// duration before retrying
func Constant(interval time.Duration) (Strategy, string) {
	if interval < 0 {
		panic("constant retry strategies must have a positive interval")
	}

	return func(r *Retrier) time.Duration {
		return interval + r.Jitter()
	}, constantStrategy
}

// Exponential returns a strategy that increases expontially based on the number of attempts the retrier has made
// It uses the calculation: adjustment + (base ** attempts) + jitter
func Exponential(base, adjustment time.Duration) (Strategy, string) {
	if base < 1*time.Second {
		panic("exponential retry strategies must have a base of at least 1 second")
	}

	return func(r *Retrier) time.Duration {
		baseSeconds := int(base / time.Second)
		exponentSeconds := math.Pow(float64(baseSeconds), float64(r.attemptCount))
		exponent := time.Duration(exponentSeconds) * time.Second

		return adjustment + exponent + r.Jitter()
	}, exponentialStrategy
}

// ExponentialSubsecond is an exponential backoff using milliseconds as a base unit,
// and so handles sub-second intervals.
//
// Formula is:
//   delayMilliseconds = initialMilliseconds ** (retries/16 + 1)

// The 16 exponent-divisor is arbitrarily chosen to scale curves nicely for a reasonable range
// of initial delays and number of attempts (e.g. 1 second, 10 attempts).
//
// Examples of a small, medium and large initial time.Second growing over 10 attempts:
//
//	100ms → 133ms → 177ms → 237ms → 316ms → 421ms → 562ms → 749ms → 1000ms
//	1.0s  → 1.5s  → 2.4s  → 3.7s  → 5.6s  → 8.7s  → 13.3s → 20.6s → 31.6s
//	5s    → 9s    → 14s   → 25s   → 42s   → 72s   → 120s  → 208s  → 354s
func ExponentialSubsecond(initial time.Duration) (Strategy, string) {
	if initial < 1*time.Millisecond {
		panic("ExponentialSubsecond retry strategies must have an initial delay of at least 1 millisecond")
	}

	return func(r *Retrier) time.Duration {
		result := math.Pow(float64(initial/time.Millisecond), float64(r.attemptCount)/16+1.0)

		return time.Duration(result)*time.Millisecond + r.Jitter()
	}, exponentialStrategy
}

type retrierOpt func(*Retrier)

// WithMaxAttempts sets the maximum number of retries that a retrier will attempt
func WithMaxAttempts(maxAttempts int) retrierOpt {
	return func(r *Retrier) {
		r.maxAttempts = maxAttempts
	}
}

func WithRand(rand *rand.Rand) retrierOpt {
	return func(r *Retrier) {
		r.rand = rand
	}
}

// WithStrategy sets the retry strategy that the retrier will use to determine how long to wait between retries
func WithStrategy(strategy Strategy, strategyType string) retrierOpt {
	return func(r *Retrier) {
		r.strategyType = strategyType
		r.intervalCalculator = strategy
	}
}

// WithJitter enables jitter on the retrier, which will cause all of the retries to wait a random amount of time < 1 second
// The idea here is to avoid thundering herds - retries that are in parallel will happen at slightly different times when
// jitter is enabled, whereas if jitter is disabled, all the retries might happen at the same time, causing further load
// on the system that we're tryung to do something with
func WithJitter() retrierOpt {
	return func(r *Retrier) {
		r.jitter = true
	}
}

// TryForever causes the retrier to to never give up retrying, until either the operation succeeds, or the operation
// calls retrier.Break()
func TryForever() retrierOpt {
	return func(r *Retrier) {
		r.forever = true
	}
}

// WithSleepFunc sets the function that the retrier uses to sleep between successive attempts
// Only really useful for testing
func WithSleepFunc(f func(time.Duration)) retrierOpt {
	return func(r *Retrier) {
		r.sleepFunc = f
	}
}

// NewRetrier creates a new instance of the Retrier struct. Pass in retrierOpt functions to customise the behaviour of
// the retrier
func NewRetrier(opts ...retrierOpt) *Retrier {
	r := &Retrier{
		rand: defaultRandom,
	}

	for _, o := range opts {
		o(r)
	}

	// We use panics here rather than returning an error because all of these are logical issues caused by the programmer,
	// they should never occur in normal running, and can't be logically recovered from
	if r.maxAttempts == 0 && !r.forever {
		panic("retriers must either run forever, or have a maximum attempt count")
	}

	if r.maxAttempts < 0 {
		panic("retriers must have a positive max attempt count")
	}

	oldJitter := r.jitter
	r.jitter = false // Temporarily turn off jitter while we check if the interval is 0
	if r.forever && r.strategyType == constantStrategy && r.NextInterval() == 0 {
		panic("retriers using the constant strategy that run forever must have an interval")
	}
	r.jitter = oldJitter // and now set it back to what it was previously

	return r
}

// Jitter returns a duration in the interval (0, 1] s if jitter is enabled, or 0 s if it's not
func (r *Retrier) Jitter() time.Duration {
	if !r.jitter {
		return 0
	}
	return time.Duration((1.0 - r.rand.Float64()) * float64(jitterInterval))
}

// MarkAttempt increments the attempt count for the retrier. This affects ShouldGiveUp, and also affects the retry interval
// for Exponential retry strategy
func (r *Retrier) MarkAttempt() {
	r.attemptCount += 1
}

// Break causes the Retrier to stop retrying after it completes the next retry cycle
func (r *Retrier) Break() {
	r.breakNext = true
}

// SetNextInterval overrides the strategy for the interval before the next try
func (r *Retrier) SetNextInterval(d time.Duration) {
	r.manualInterval = &d
}

// ShouldGiveUp returns whether the retrier should stop trying do do the thing it's been asked to do
// It returns true if the retry count is greater than r.maxAttempts, or if r.Break() has been called
// It returns false if the retrier is supposed to try forever
func (r *Retrier) ShouldGiveUp() bool {
	if r.breakNext {
		return true
	}

	if r.forever {
		return false
	}

	return r.attemptCount >= r.maxAttempts
}

// NextInterval returns the next interval that the retrier will use. Behind the scenes, it calls the function generated
// by either retrier's strategy
func (r *Retrier) NextInterval() time.Duration {
	if r.manualInterval != nil {
		return *r.manualInterval
	}

	return r.intervalCalculator(r)
}

func (r *Retrier) String() string {
	str := fmt.Sprintf("Attempt %d/", r.attemptCount+1) // +1 because we increment the attempt count after the callback, which is the only useful place to call Retrier.String()

	if r.forever {
		str = str + "∞"
	} else {
		str = str + fmt.Sprintf("%d", r.maxAttempts)
	}

	if r.attemptCount+1 == r.maxAttempts {
		return str
	}

	nextInterval := r.NextInterval()
	if nextInterval > 0 {
		str = str + fmt.Sprintf(" Retrying in %s", nextInterval)
	} else {
		str = str + " Retrying immediately"
	}

	return str
}

func (r *Retrier) AttemptCount() int {
	return r.attemptCount
}

// Do is the core loop of a Retrier. It defines the operation that the Retrier will attempt to perform, retrying it if necessary
// Calling retrier.Do(someFunc) will cause the Retrier to attempt to call the function, and if it returns an error,
// retry it using the settings provided to it.
func (r *Retrier) Do(callback func(*Retrier) error) error {
	return r.DoWithContext(context.Background(), callback)
}

// DoWithContext is a context-aware variant of Do.
func (r *Retrier) DoWithContext(ctx context.Context, callback func(*Retrier) error) error {
	for {
		// Perform the action the user has requested we retry
		err := callback(r)
		if err == nil {
			return nil
		}

		// Calculate the next interval before we increment the attempt count
		// In the exponential case, if we didn't do this, we'd skip the first interval
		// ie, we would wait 2^1, 2^2, 2^3, ..., 2^n+1 seconds (bad)
		// instead of        2^0, 2^1, 2^2, ..., 2^n seconds (good)
		nextInterval := r.NextInterval()

		// Reset the manualInterval now that the nextInterval has been acquired.
		r.manualInterval = nil

		r.MarkAttempt()

		// If the last callback called r.Break(), or if we've hit our call limit, bail out and return the last error we got
		if r.ShouldGiveUp() {
			return err
		}

		if err := r.sleepOrDone(ctx, nextInterval); err != nil {
			return err
		}
	}
}

// DoFunc is a helper for retrying callback functions that return a value or an
// error. It returns the last value returned by a call to callback, and reports
// an error if none of the calls succeeded.
// (Note this is not a method of Retrier, since methods can't be generic.)
func DoFunc[T any](ctx context.Context, r *Retrier, callback func(*Retrier) (T, error)) (T, error) {
	var t T
	err := r.DoWithContext(ctx, func(rt *Retrier) error {
		var err error
		t, err = callback(rt)
		return err
	})
	return t, err
}

// DoFunc2 is a helper for retrying callback functions that return two value or
// an error. It returns the last values returned by a call to callback, and
// reports an error if none of the calls succeeded.
// (Note this is not a method of Retrier, since methods can't be generic.)
func DoFunc2[T1, T2 any](ctx context.Context, r *Retrier, callback func(*Retrier) (T1, T2, error)) (T1, T2, error) {
	var t1 T1
	var t2 T2
	err := r.DoWithContext(ctx, func(rt *Retrier) error {
		var err error
		t1, t2, err = callback(rt)
		return err
	})
	return t1, t2, err
}

// DoFunc3 is a helper for retrying callback functions that return 3 values or
// an error. It returns the last values returned by a call to callback, and
// reports an error if none of the calls succeeded.
// (Note this is not a method of Retrier, since methods can't be generic.)
func DoFunc3[T1, T2, T3 any](ctx context.Context, r *Retrier, callback func(*Retrier) (T1, T2, T3, error)) (T1, T2, T3, error) {
	var t1 T1
	var t2 T2
	var t3 T3
	err := r.DoWithContext(ctx, func(rt *Retrier) error {
		var err error
		t1, t2, t3, err = callback(rt)
		return err
	})
	return t1, t2, t3, err
}

func (r *Retrier) sleepOrDone(ctx context.Context, nextInterval time.Duration) error {
	if r.sleepFunc == nil {
		t := time.NewTimer(nextInterval)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	sleepCh := make(chan struct{})
	go func() {
		r.sleepFunc(nextInterval)
		close(sleepCh)
	}()
	select {
	case <-sleepCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
