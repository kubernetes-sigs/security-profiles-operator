// Copyright 2024 The Sigstore Authors.
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
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitorus/timestamp"
)

type TimestampAuthorityOptions struct {
	// Full URL (with path) of Timestamp Authority endpoint
	URL string
	// Optional timeout for the whole request including retries (default 30s; use negative value for no timeout)
	Timeout time.Duration
	// Optional number of times to retry on transient failures (connection errors, HTTP 429, HTTP 5xx other than 501); zero disables retries
	Retries uint
	// Optional base Transport (for dependency injection); it is wrapped by the retrying transport, so set Retries to 0 if it already retries
	Transport http.RoundTripper
	// Optional User-Agent prefix for requests; sigstore-go/<version> is always appended
	UserAgent string
}

type TimestampAuthority struct {
	options *TimestampAuthorityOptions
	client  *http.Client
}

var TimestampAuthorityAPIVersions = []uint32{1}

func NewTimestampAuthority(opts *TimestampAuthorityOptions) *TimestampAuthority {
	ta := &TimestampAuthority{options: opts}
	ta.client = &http.Client{
		Transport: newRetryTransport(opts.Transport, opts.Retries),
	}

	if opts.Timeout >= 0 {
		if opts.Timeout == 0 {
			opts.Timeout = 30 * time.Second
		}
		ta.client.Timeout = opts.Timeout
	}

	return ta
}

func (ta *TimestampAuthority) GetTimestamp(ctx context.Context, signature []byte) ([]byte, error) {
	signatureHash := sha256.Sum256(signature)

	req := &timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: signatureHash[:],
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	// Transient failures are retried by the client's transport; see
	// newRetryTransport.
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ta.options.URL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/timestamp-query")
	request.Header.Add("User-Agent", userAgent(ta.options.UserAgent))

	response, err := ta.client.Do(request) // #nosec G704 -- Client controls the URL
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 && response.StatusCode != 201 {
		return nil, fmt.Errorf("timestamp authority returned %d: %s", response.StatusCode, string(body))
	}

	_, err = timestamp.ParseResponse(body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
