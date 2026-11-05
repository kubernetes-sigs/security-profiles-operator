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

package sign

import (
	"math"
	"net/http"

	"github.com/sigstore/sigstore/pkg/httpretry"
)

// newRetryTransport wraps base (nil means http.DefaultTransport) in an
// httpretry.Transport that retries transient failures (connection errors,
// HTTP 429, and HTTP 5xx other than 501) up to retries times, using jittered
// exponential backoff that honors Retry-After. A retries value of zero
// disables retrying.
func newRetryTransport(base http.RoundTripper, retries uint) *httpretry.Transport {
	transport := httpretry.NewTransport(base)
	// Bound the conversion so it cannot overflow.
	maxRetries := math.MaxInt
	if retries < math.MaxInt {
		maxRetries = int(retries)
	}
	transport.MaxRetries = maxRetries
	return transport
}
