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

// Package integration contains the integration tests of the manager
// controllers. They run every controller against a real API server and etcd
// provided by envtest, which the fake client cannot replace: the tests cover
// the watches, predicates, field indexes and map functions a controller
// registers, and the status subresource and finalizer handling of the API
// server. The tests are only built with the "integration" build tag and need
// the envtest binaries, see the test-integration Makefile target.
package integration
