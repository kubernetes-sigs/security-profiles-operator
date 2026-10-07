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

package workloadtracker

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const testFinalizer = "test-finalizer"

var errTest = errors.New("test")

func newTracker(
	t *testing.T, funcs *interceptor.Funcs, objs ...client.Object,
) (*Tracker[*profilebindingapi.ProfileBinding], client.Client) {
	t.Helper()

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&profilebindingapi.ProfileBinding{}).
		WithInterceptorFuncs(*funcs).
		Build()

	return &Tracker[*profilebindingapi.ProfileBinding]{
		Client:    c,
		Reader:    c,
		Finalizer: testFinalizer,
		Kind:      "ProfileBinding",
		Workloads: func(pb *profilebindingapi.ProfileBinding) *[]string {
			return &pb.Status.ActiveWorkloads
		},
	}, c
}

func testBinding() *profilebindingapi.ProfileBinding {
	return &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "ns"},
	}
}

func stored(t *testing.T, c client.Client) *profilebindingapi.ProfileBinding {
	t.Helper()

	pb := &profilebindingapi.ProfileBinding{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(testBinding()), pb))

	return pb
}

func TestTrackAndUntrack(t *testing.T) {
	t.Parallel()

	sut, c := newTracker(t, &interceptor.Funcs{}, testBinding())

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-b"))
	// Tracking a workload twice keeps it once.
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))

	pb := stored(t, c)
	require.Equal(t, []string{"pod-a", "pod-b"}, pb.Status.ActiveWorkloads)
	require.Contains(t, pb.Finalizers, testFinalizer)

	// The finalizer stays while a workload is left.
	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-a"))
	pb = stored(t, c)
	require.Equal(t, []string{"pod-b"}, pb.Status.ActiveWorkloads)
	require.Contains(t, pb.Finalizers, testFinalizer)

	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-b"))
	pb = stored(t, c)
	require.Empty(t, pb.Status.ActiveWorkloads)
	require.NotContains(t, pb.Finalizers, testFinalizer)
}

func TestTrackRetriesConflicts(t *testing.T) {
	t.Parallel()

	conflicts := 0

	sut, c := newTracker(t, &interceptor.Funcs{
		SubResourceUpdate: func(
			ctx context.Context, cl client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption,
		) error {
			if conflicts == 0 {
				conflicts++

				return kerrors.NewConflict(schema.GroupResource{}, obj.GetName(), errTest)
			}

			return cl.SubResource(sub).Update(ctx, obj, opts...)
		},
	}, testBinding())

	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.Equal(t, 1, conflicts)
	require.Equal(t, []string{"pod-a"}, stored(t, c).Status.ActiveWorkloads)
}

func TestTrackMissingObject(t *testing.T) {
	t.Parallel()

	// An object which is gone has no workloads to track.
	sut, _ := newTracker(t, &interceptor.Funcs{})
	require.NoError(t, sut.Track(t.Context(), testBinding(), "pod-a"))
	require.NoError(t, sut.Untrack(t.Context(), testBinding(), "pod-a"))
}

func TestTrackErrors(t *testing.T) {
	t.Parallel()

	sut, _ := newTracker(t, &interceptor.Funcs{
		Get: func(
			context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption,
		) error {
			return errTest
		},
	}, testBinding())

	require.ErrorIs(t, sut.Track(t.Context(), testBinding(), "pod-a"), errTest)
	require.ErrorIs(t, sut.Untrack(t.Context(), testBinding(), "pod-a"), errTest)
}
