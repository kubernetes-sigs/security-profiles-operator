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

package artifact

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// TestTransport verifies that the registry requests do not share the pool of
// connections of http.DefaultTransport, whose idle connections
// httptest.Server.Close closes, but keep its proxy settings.
func TestTransport(t *testing.T) {
	t.Parallel()

	transport, ok := Transport().(*http.Transport)
	require.True(t, ok)
	require.NotSame(t, http.DefaultTransport, transport)
	require.NotNil(t, transport.Proxy)
	require.Same(t, transport, Transport())

	client := HTTPClient()
	retrying, ok := client.Transport.(*retry.Transport)
	require.True(t, ok)
	require.Same(t, transport, retrying.Base)
	require.Same(t, client, HTTPClient())
}
