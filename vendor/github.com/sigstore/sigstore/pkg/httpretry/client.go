//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpretry

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultMaxRetries is the default number of times to retry a failed request.
	DefaultMaxRetries = 4
	// DefaultWaitMin is the default minimum time to wait between attempts.
	DefaultWaitMin = time.Second
	// DefaultWaitMax is the default maximum time to wait between attempts.
	DefaultWaitMax = 30 * time.Second
)

const drainBodyLimit = 2 * 1024 * 1024

// CheckRetry decides whether a response or error should be retried.
type CheckRetry func(req *http.Request, resp *http.Response, err error) bool

// Backoff decides how long to wait before the next attempt.
type Backoff func(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration

// Transport is an HTTP transport that retries transient failures. A Transport
// must not be modified after first use.
type Transport struct {
	// Base is the underlying transport used for each attempt. If nil,
	// http.DefaultTransport is used.
	Base http.RoundTripper
	// MaxRetries is the number of times a failed request is retried.
	MaxRetries int
	// WaitMin is the minimum backoff between attempts.
	WaitMin time.Duration
	// WaitMax is the maximum backoff between attempts.
	WaitMax time.Duration
	// CheckRetry decides which responses and errors are retried. If nil,
	// DefaultRetryPolicy is used.
	CheckRetry CheckRetry
	// Backoff decides how long to wait between retries. If nil, DefaultBackoff
	// is used.
	Backoff Backoff
}

// NewClient returns an HTTP client with a retrying transport.
func NewClient() *http.Client {
	return &http.Client{
		Transport: NewTransport(nil),
	}
}

// NewTransport returns a transport with the default retry settings.
func NewTransport(base http.RoundTripper) *Transport {
	return &Transport{
		Base:       base,
		MaxRetries: DefaultMaxRetries,
		WaitMin:    DefaultWaitMin,
		WaitMax:    DefaultWaitMax,
		CheckRetry: DefaultRetryPolicy,
		Backoff:    DefaultBackoff,
	}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("httpretry: nil request")
	}

	transport := t.Base
	if transport == nil {
		transport = http.DefaultTransport
	}

	checkRetry := t.CheckRetry
	if checkRetry == nil {
		checkRetry = DefaultRetryPolicy
	}

	backoff := t.Backoff
	if backoff == nil {
		backoff = DefaultBackoff
	}

	maxRetries := max(t.MaxRetries, 0)
	if !canReplayRequest(req) {
		maxRetries = 0
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		attemptReq := req
		if attempt > 0 {
			attemptReq, err = cloneRequest(req)
			if err != nil {
				return nil, err
			}
		}

		resp, err = transport.RoundTrip(attemptReq)
		if !checkRetry(req, resp, err) || attempt == maxRetries {
			return resp, err
		}

		drainAndClose(resp)
		if err := sleep(req.Context(), backoff(t.WaitMin, t.WaitMax, attempt, resp)); err != nil {
			return nil, err
		}
	}

	return resp, err
}

// DefaultRetryPolicy retries connection errors, HTTP 429, and HTTP 5xx
// responses except 501. It does not retry context cancellation, context
// deadlines, TLS certificate errors, invalid protocol configuration, or
// redirect-limit failures.
func DefaultRetryPolicy(req *http.Request, resp *http.Response, err error) bool {
	if req != nil && req.Context().Err() != nil {
		return false
	}
	if err != nil {
		return retryableError(err)
	}
	if resp == nil {
		return false
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return true
	case resp.StatusCode == 0:
		return true
	case resp.StatusCode >= http.StatusInternalServerError && resp.StatusCode != http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

// DefaultBackoff returns an exponential backoff delay with jitter, capped
// between min and max. It honors Retry-After for HTTP 429 and 503 responses
// when present.
func DefaultBackoff(waitMin, waitMax time.Duration, attempt int, resp *http.Response) time.Duration {
	if waitMin <= 0 || waitMax <= 0 {
		return 0
	}
	if waitMin > waitMax {
		return waitMax
	}
	if retryAfter := retryAfterDelay(resp); retryAfter > 0 {
		if retryAfter > waitMax {
			return waitMax
		}
		return retryAfter
	}
	delay := waitMin
	for range attempt {
		if delay >= waitMax/2 {
			return waitMax
		}
		delay *= 2
	}
	return jitter(waitMin, delay)
}

func retryableError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Err == nil {
			return false
		}
		msg := urlErr.Err.Error()
		if strings.Contains(msg, "stopped after") && strings.Contains(msg, "redirects") {
			return false
		}
		if strings.Contains(msg, "unsupported protocol scheme") || strings.Contains(msg, "invalid header") {
			return false
		}
	}

	var unknownAuthority x509.UnknownAuthorityError
	var certificateInvalid x509.CertificateInvalidError
	var hostnameError x509.HostnameError
	return !errors.As(err, &unknownAuthority) && !errors.As(err, &certificateInvalid) && !errors.As(err, &hostnameError)
}

func retryAfterDelay(resp *http.Response) time.Duration {
	if resp == nil || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) {
		return 0
	}
	value := resp.Header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	retryTime, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	if delay := time.Until(retryTime); delay > 0 {
		return delay
	}
	return 0
}

func jitter(waitMin, waitMax time.Duration) time.Duration {
	if waitMin >= waitMax {
		return waitMin
	}
	// #nosec G404 -- retry jitter only spreads load and is not used for security.
	return waitMin + rand.N(waitMax-waitMin)
}

func canReplayRequest(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	return clone, nil
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainBodyLimit))
	_ = resp.Body.Close()
}

func sleep(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
