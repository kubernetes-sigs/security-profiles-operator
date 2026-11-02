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
	"sync"

	"oras.land/oras-go/v2/registry/remote/retry"
)

// Transport returns the transport of the registry, token and TUF requests:
// a clone of http.DefaultTransport, which keeps its proxy and TLS settings,
// but not its pool of connections. Whoever calls CloseIdleConnections on
// http.DefaultTransport, like httptest.Server.Close does, would otherwise
// break the connection a request is about to reuse, and a failed PUT does
// not get retried. The clone is shared, so that the daemon, which pulls with
// a new Artifact each time, keeps reusing its connections.
func Transport() http.RoundTripper {
	return transport()
}

var transport = sync.OnceValue(func() http.RoundTripper {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		return t.Clone()
	}

	// Another program may have replaced it with a transport which cannot be
	// cloned, which is then used as it is.
	return http.DefaultTransport
})

// HTTPClient returns the client of the registry and token requests, which
// retries like retry.DefaultClient of oras, over Transport.
func HTTPClient() *http.Client {
	return httpClient()
}

var httpClient = sync.OnceValue(func() *http.Client {
	return &http.Client{Transport: retry.NewTransport(Transport())}
})
