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

package recordingmerger

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

func recording(deleted bool) *profilerecordingapi.ProfileRecording {
	r := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "recording",
			Namespace: "ns",
			// The merger only ever sees recordings that still hold this
			// finalizer, which is exactly why the deletion reaches it as an
			// update rather than as a delete event.
			Finalizers: []string{profilerecordingapi.RecordingHasUnmergedProfiles},
		},
	}

	if deleted {
		now := metav1.NewTime(time.Now())
		r.DeletionTimestamp = &now
	}

	return r
}

// The merger acts only on the deletion branch of Reconcile. Filtering updates
// out drops the only event that carries the deletion timestamp, and the
// finalizer prevents the delete event from ever firing, so merging stops
// happening entirely and recordings hang in Terminating.
func TestMergePredicate(t *testing.T) {
	t.Parallel()

	p := mergePredicate()

	t.Run("update setting the deletion timestamp is accepted", func(t *testing.T) {
		t.Parallel()

		require.True(t, p.Update(event.UpdateEvent{
			ObjectOld: recording(false),
			ObjectNew: recording(true),
		}))
	})

	t.Run("update of a live recording is ignored", func(t *testing.T) {
		t.Parallel()

		require.False(t, p.Update(event.UpdateEvent{
			ObjectOld: recording(false),
			ObjectNew: recording(false),
		}))
	})

	t.Run("update without a new object is ignored", func(t *testing.T) {
		t.Parallel()

		require.False(t, p.Update(event.UpdateEvent{ObjectOld: recording(false)}))
	})

	t.Run("create is ignored", func(t *testing.T) {
		t.Parallel()

		require.False(t, p.Create(event.CreateEvent{Object: recording(false)}))
	})

	t.Run("generic is ignored", func(t *testing.T) {
		t.Parallel()

		require.False(t, p.Generic(event.GenericEvent{Object: recording(false)}))
	})

	t.Run("delete is accepted", func(t *testing.T) {
		t.Parallel()

		require.True(t, p.Delete(event.DeleteEvent{Object: recording(true)}))
	})
}
