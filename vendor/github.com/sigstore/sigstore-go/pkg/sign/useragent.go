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
	"net/http"

	"github.com/sigstore/sigstore-go/pkg/util"
)

// userAgent returns the default sigstore-go User-Agent, prefixed with ua if set,
// so the underlying SDK is always identified.
func userAgent(ua string) string {
	if ua != "" {
		return ua + " " + util.ConstructUserAgent()
	}
	return util.ConstructUserAgent()
}

// userAgentTransport adds the configured User-Agent to each request.
type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (t userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.userAgent)
	return t.base.RoundTrip(req)
}
