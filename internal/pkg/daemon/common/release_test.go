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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func newStatusClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()

	return fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		Build()
}

// The deleted profile of a kind which the SPOD disabled gets released by the
// node which installed it while the kind was enabled.
func TestReleaseController(t *testing.T) {
	t.Parallel()

	profile := testProfile()
	cl := newStatusClient(t, profile)

	_, err := testNodeStatus(t, profile, cl).Create(t.Context())
	require.NoError(t, err)

	r := NewReleaseController(
		"seccomp-spod",
		func() profilebase.SecurityProfileBase { return &seccompprofileapi.SeccompProfile{} },
		seccompprofileapi.SchemeBuilder,
	)
	r.client = cl
	r.reader = cl
	r.log = log.Log
	r.nodeName = testNodeName

	require.Equal(t, "seccomp-spod-release", r.Name())

	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(profile)}

	// A profile which is not being deleted keeps the finalizer.
	res, err := r.Reconcile(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	stored := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, cl.Get(t.Context(), req.NamespacedName, stored))
	require.NotEmpty(t, stored.GetFinalizers())

	require.NoError(t, cl.Delete(t.Context(), stored))

	res, err = r.Reconcile(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	err = cl.Get(t.Context(), req.NamespacedName, &seccompprofileapi.SeccompProfile{})
	require.True(t, kerrors.IsNotFound(err), "the profile is gone: %v", err)

	statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	require.NoError(t, cl.List(t.Context(), statuses))
	require.Empty(t, statuses.Items)

	// A profile which is gone has nothing left to release.
	res, err = r.Reconcile(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
}

// A node known not to support the kind marks its node status as unsupported:
// an error for an enabled profile, the disabled state for a disabled one. The
// status gets created without the finalizer of the node.
func TestReconcileUnsupported(t *testing.T) {
	t.Parallel()

	errUnsupported := errors.New("node does not support the kind")

	profile := testProfile()
	key := client.ObjectKeyFromObject(profile)
	cl := newStatusClient(t, profile)

	var written nodestatus.WrittenStates

	// reconcileProfile reconciles the stored profile and returns it with its
	// node status.
	reconcileProfile := func() (
		*seccompprofileapi.SeccompProfile, *secprofnodestatusapi.SecurityProfileNodeStatus,
	) {
		t.Helper()

		stored := &seccompprofileapi.SeccompProfile{}
		require.NoError(t, cl.Get(t.Context(), key, stored))
		require.NoError(t, ReconcileUnsupported(
			t.Context(), cl, cl, stored, testNodeName, &written, errUnsupported,
		))
		require.NoError(t, cl.Get(t.Context(), key, stored))

		statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
		require.NoError(t, cl.List(t.Context(), statuses))
		require.Len(t, statuses.Items, 1)

		return stored, &statuses.Items[0]
	}

	stored, status := reconcileProfile()
	require.True(t, nodestatus.IsUnsupported(status))
	require.Equal(t, secprofnodestatusapi.ProfileStateError, status.Status.Status)
	require.Equal(t, errUnsupported.Error(), status.Status.Message)
	require.Empty(t, stored.GetFinalizers(), "nothing on the node to remove")

	stored.Spec.State = profilebase.SpecStateDisabled
	require.NoError(t, cl.Update(t.Context(), stored))

	_, status = reconcileProfile()
	require.True(t, nodestatus.IsUnsupported(status))
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, status.Status.Status)
	require.Empty(t, status.Status.Message)

	// A node which supports the kind again turns it into a regular status
	// with the finalizer of the node.
	stored = &seccompprofileapi.SeccompProfile{}
	require.NoError(t, cl.Get(t.Context(), key, stored))

	nsc := testNodeStatus(t, stored, cl)
	nsc.WithAPIReader(cl)
	_, _, err := EnsureNodeStatus(t.Context(), nsc, log.Log)
	require.NoError(t, err)

	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(status), status))
	require.False(t, nodestatus.IsUnsupported(status))
	require.NoError(t, cl.Get(t.Context(), key, stored))
	require.NotEmpty(t, stored.GetFinalizers())

	// A profile which could not be read is left alone.
	require.NoError(t, ReconcileUnsupported(
		t.Context(), cl, cl, &seccompprofileapi.SeccompProfile{}, testNodeName, &written,
		errUnsupported,
	))
}

// A node which lost the support of the kind keeps the finalizer it added
// before, which gets released once the profile is deleted.
func TestReconcileUnsupportedReleasesFinalizer(t *testing.T) {
	t.Parallel()

	errUnsupported := errors.New("node does not support the kind")

	profile := testProfile()
	key := client.ObjectKeyFromObject(profile)
	cl := newStatusClient(t, profile)

	_, err := testNodeStatus(t, profile, cl).Create(t.Context())
	require.NoError(t, err)

	var written nodestatus.WrittenStates

	stored := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, cl.Get(t.Context(), key, stored))
	require.NoError(t, ReconcileUnsupported(
		t.Context(), cl, cl, stored, testNodeName, &written, errUnsupported,
	))

	statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	require.NoError(t, cl.List(t.Context(), statuses))
	require.Len(t, statuses.Items, 1)
	require.True(t, nodestatus.IsUnsupported(&statuses.Items[0]))

	require.NoError(t, cl.Get(t.Context(), key, stored))
	require.NotEmpty(t, stored.GetFinalizers())
	require.NoError(t, cl.Delete(t.Context(), stored))
	require.NoError(t, cl.Get(t.Context(), key, stored))
	require.NoError(t, ReconcileUnsupported(
		t.Context(), cl, cl, stored, testNodeName, &written, errUnsupported,
	))

	err = cl.Get(t.Context(), key, &seccompprofileapi.SeccompProfile{})
	require.True(t, kerrors.IsNotFound(err), "the profile is gone: %v", err)
}
