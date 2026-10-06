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

package common

import (
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/event"

	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
)

// The periodic resyncs of the daemon cache pass, so that a profile which got
// removed from the host is installed again, while writes of the object do not.
func TestResyncPredicate(t *testing.T) {
	t.Parallel()

	old := testProfile()
	old.ResourceVersion = "1"

	require.True(t, ResyncPredicate.Update(event.UpdateEvent{
		ObjectOld: old,
		ObjectNew: old.DeepCopy(),
	}))

	written := old.DeepCopy()
	written.ResourceVersion = "2"
	written.Status.Status = secprofnodestatusapi.ProfileStateInstalled

	require.False(t, ResyncPredicate.Update(event.UpdateEvent{
		ObjectOld: old,
		ObjectNew: written,
	}))

	require.False(t, ResyncPredicate.Update(event.UpdateEvent{ObjectNew: old}))
}
