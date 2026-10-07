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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

var errMergeTest = errors.New("test")

// newFailingMergeReconciler returns a reconciler whose client fails as funcs
// tells, with a deleted recording and a partial profile.
func newFailingMergeReconciler(
	t *testing.T, funcs *interceptor.Funcs,
) (*PolicyMergeReconciler, client.Client, *events.FakeRecorder) {
	t.Helper()

	recorder := events.NewFakeRecorder(20)
	cl := fake.NewClientBuilder().
		WithScheme(mergerTestScheme(t)).
		WithObjects(
			testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true),
			partialSeccomp("partial-a", "nginx", "read"),
		).
		WithInterceptorFuncs(*funcs).
		Build()

	return &PolicyMergeReconciler{client: cl, log: logr.Discard(), record: recorder}, cl, recorder
}

func recordedEvents(recorder *events.FakeRecorder) string {
	var all []string

	for len(recorder.Events) > 0 {
		all = append(all, <-recorder.Events)
	}

	return strings.Join(all, "\n")
}

// A merged profile which cannot be written keeps the partial profiles, so that
// the merge can be retried.
func TestMergeProfilesCreateError(t *testing.T) {
	t.Parallel()

	r, cl, recorder := newFailingMergeReconciler(t, &interceptor.Funcs{
		Create: func(
			context.Context, client.WithWatch, client.Object, ...client.CreateOption,
		) error {
			return errMergeTest
		},
	})

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	require.ErrorIs(t, r.mergeProfiles(t.Context(), recording), errMergeTest)
	require.Contains(t, recordedEvents(recorder), reasonCannotCreateUpdate)

	partials := &seccompprofile.SeccompProfileList{}
	require.NoError(t, cl.List(t.Context(), partials))
	require.Len(t, partials.Items, 1)
}

// The partial profiles which cannot be listed are not merged.
func TestMergeProfilesListError(t *testing.T) {
	t.Parallel()

	r, _, _ := newFailingMergeReconciler(t, &interceptor.Funcs{
		List: func(
			context.Context, client.WithWatch, client.ObjectList, ...client.ListOption,
		) error {
			return errMergeTest
		},
	})

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	require.ErrorIs(t, r.mergeProfiles(t.Context(), recording), errMergeTest)
}

// A partial profile which cannot be deleted after the merge fails the merge,
// which gets retried, while the merged profile is kept.
func TestMergeProfilesDeleteError(t *testing.T) {
	t.Parallel()

	r, cl, _ := newFailingMergeReconciler(t, &interceptor.Funcs{
		Delete: func(
			context.Context, client.WithWatch, client.Object, ...client.DeleteOption,
		) error {
			return errMergeTest
		},
	})

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	require.ErrorIs(t, r.mergeProfiles(t.Context(), recording), errMergeTest)
	require.Equal(t, []string{"read"}, mergedSyscallsOf(t, cl, testRecording+"-nginx"))
}
