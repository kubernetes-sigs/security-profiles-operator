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

package podindex

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
)

// TestFindIn asserts that one list of the pods tells whether a pod has the
// container and whether one has pending containers. A pod which reported the
// container in the meantime is found, even next to other pending containers,
// instead of the container being reported as not found.
func TestFindIn(t *testing.T) {
	t.Parallel()

	id := strings.Repeat("1", 64)
	running := podindextest.Pod("ns", "running", "container", id)
	pending := podindextest.Pod("ns", "pending", "container", "")
	other := podindextest.Pod("ns", "other", "container", strings.Repeat("2", 64))

	pod, wait := findIn([]any{pending, running}, id)
	require.Same(t, running, pod)
	require.False(t, wait)

	pod, wait = findIn([]any{other, pending}, id)
	require.Nil(t, pod)
	require.True(t, wait)

	pod, wait = findIn([]any{other}, id)
	require.Nil(t, pod)
	require.False(t, wait)

	pod, wait = findIn(nil, id)
	require.Nil(t, pod)
	require.False(t, wait)
}
