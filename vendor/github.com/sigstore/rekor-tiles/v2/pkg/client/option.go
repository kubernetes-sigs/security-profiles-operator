//
// Copyright 2025 The Sigstore Authors.
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

package client

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"
)

// Config contains connection options for the client.
type Config struct {
	UserAgent string
	Timeout   time.Duration
	TLSConfig *tls.Config
	Transport http.RoundTripper
}

// Option customizes the client Config.
type Option func(*Config)

// WithUserAgent sets the user agent.
func WithUserAgent(agent string) Option {
	return func(c *Config) {
		c.UserAgent = agent
	}
}

// WithTimeout sets the timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.Timeout = timeout
	}
}

// WithTLSConfig sets the TLS config.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *Config) {
		c.TLSConfig = tlsConfig
	}
}

// WithTransport sets the base http.RoundTripper used for requests, for
// example to add retries or to inject a mock in tests. The client still wraps
// it to set the User-Agent. It is mutually exclusive with WithTLSConfig.
func WithTransport(transport http.RoundTripper) Option {
	return func(c *Config) {
		c.Transport = transport
	}
}

// BaseTransport returns the http.RoundTripper selected by the config: the
// transport set with WithTransport, otherwise an http.Transport using the TLS
// config set with WithTLSConfig, otherwise http.DefaultTransport. It returns an
// error if both a transport and a TLS config were set, since a TLS config
// cannot be applied to an arbitrary RoundTripper.
func (c *Config) BaseTransport() (http.RoundTripper, error) {
	switch {
	case c.Transport != nil && c.TLSConfig != nil:
		return nil, errors.New("WithTransport and WithTLSConfig are mutually exclusive")
	case c.Transport != nil:
		return c.Transport, nil
	case c.TLSConfig != nil:
		return &http.Transport{
			TLSClientConfig: c.TLSConfig,
		}, nil
	default:
		return http.DefaultTransport, nil
	}
}
