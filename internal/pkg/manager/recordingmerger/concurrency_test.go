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
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func mergedSyscallsOf(t *testing.T, cl client.Client, name string) []string {
	t.Helper()

	merged := &seccompprofile.SeccompProfile{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{Name: name}, merged))

	var names []string
	for _, s := range merged.Spec.Syscalls {
		names = append(names, s.Names...)
	}

	return names
}

func mergeSyscalls(
	t *testing.T,
	cl client.Client,
	recording *profilerecordingapi.ProfileRecording,
	name string,
	syscalls ...string,
) error {
	t.Helper()

	partial, err := newMergeableProfile(partialSeccomp("partial", "nginx", syscalls...))
	require.NoError(t, err)

	_, err = createUpdateSeccompProfile(t.Context(), cl, recording, name, partial, "")

	return err
}

// Another writer, like the profile recorder of a node, may change the merged
// profile between reading and writing it. The write then conflicts and has to
// merge into the new state instead of dropping the other writer's syscalls.
func TestCreateUpdateProfileMergesConcurrentUpdate(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	name := testRecording + "-nginx"

	interfered := false
	cl := fake.NewClientBuilder().WithScheme(mergerTestScheme(t)).WithInterceptorFuncs(
		interceptor.Funcs{
			Update: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
			) error {
				if !interfered {
					interfered = true

					// The concurrent writer wins the race.
					other := &seccompprofile.SeccompProfile{}
					require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), other))
					other.Spec.Syscalls = append(other.Spec.Syscalls, seccompprofile.Syscall{
						Action: seccompprofile.ActAllow,
						Names:  []string{"write"},
					})
					require.NoError(t, c.Update(ctx, other))
				}

				return c.Update(ctx, obj, opts...)
			},
		},
	).Build()

	require.NoError(t, mergeSyscalls(t, cl, recording, name, "read"))
	require.NoError(t, mergeSyscalls(t, cl, recording, name, "open"))

	require.True(t, interfered)
	require.ElementsMatch(t, []string{"read", "open", "write"}, mergedSyscallsOf(t, cl, name))
}

// Concurrent merges into the same profile must not lose any syscall.
func TestCreateUpdateProfileConcurrentMerges(t *testing.T) {
	t.Parallel()

	recording := testMergeRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile, true)
	name := testRecording + "-nginx"
	cl := fake.NewClientBuilder().WithScheme(mergerTestScheme(t)).Build()

	const writers = 4

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)

	want := make([]string, 0, writers)

	for i := range writers {
		syscall := fmt.Sprintf("syscall%d", i)
		want = append(want, syscall)

		wg.Go(func() {
			err := mergeSyscalls(t, cl, recording, name, syscall)

			mu.Lock()
			defer mu.Unlock()

			errs = append(errs, err)
		})
	}

	wg.Wait()

	for _, err := range errs {
		require.NoError(t, err)
	}

	require.ElementsMatch(t, want, mergedSyscallsOf(t, cl, name))
}
