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

package utiltest

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/events"
)

// RequireEvent asserts that the next event recorded by rec is want, in the
// "<type> <reason> <message>" format of the fake recorder.
func RequireEvent(t *testing.T, rec *events.FakeRecorder, want string) {
	t.Helper()

	select {
	case got := <-rec.Events:
		require.Equal(t, want, got)
	default:
		require.Failf(t, "missing event", "expected event %q, got none", want)
	}
}

// RequireNoEvent asserts that rec has no recorded event left.
func RequireNoEvent(t *testing.T, rec *events.FakeRecorder) {
	t.Helper()

	select {
	case got := <-rec.Events:
		require.Failf(t, "unexpected event", "expected no event, got %q", got)
	default:
	}
}
