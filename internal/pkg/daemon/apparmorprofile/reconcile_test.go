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

package apparmorprofile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

const (
	testNode    = "test-node"
	testProfile = "test-profile"
)

// countingProfileManager is a ProfileManager that records how the reconciler
// drives it.
type countingProfileManager struct {
	enabled bool
	// unsupported makes KnownUnsupported report a host without AppArmor,
	// instead of a failed detection.
	unsupported bool
	updated     bool
	installErr  error
	removeErr   error
	// notRemoved makes RemoveProfile report that it removed nothing.
	notRemoved bool
	// loaded makes ProfileInstalled report the profile as loaded by the
	// operator.
	loaded bool

	installs     int
	removes      int
	gotOwnedByUs bool
	// removedOwned is the ownership RemoveProfile got last.
	removedOwned bool
}

func (m *countingProfileManager) Enabled() bool {
	return m.enabled
}

func (m *countingProfileManager) KnownUnsupported() bool {
	return !m.enabled && m.unsupported
}

func (m *countingProfileManager) InstallProfile(
	_ profilebaseapi.StatusBaseUser, ownedByUs bool,
) (bool, error) {
	m.installs++
	m.gotOwnedByUs = ownedByUs

	return m.updated, m.installErr
}

func (m *countingProfileManager) ProfileInstalled(profilebaseapi.StatusBaseUser) (bool, error) {
	return m.loaded, nil
}

func (m *countingProfileManager) RemoveProfile(
	_ profilebaseapi.StatusBaseUser, ownedByUs bool,
) (bool, error) {
	m.removes++
	m.removedOwned = ownedByUs

	return m.removeErr == nil && !m.notRemoved, m.removeErr
}

func testAppArmorProfile() *apparmorprofileapi.AppArmorProfile {
	return &apparmorprofileapi.AppArmorProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apparmorprofileapi.GroupVersion.String(),
			Kind:       "AppArmorProfile",
		},
		ObjectMeta: metav1.ObjectMeta{Name: testProfile},
	}
}

// gvkSetter returns a function that restores the TypeMeta of an object after
// a successful client call. The fake client clears the TypeMeta of typed
// objects on every call, while the cached client of the manager sets it. The
// node status names derive from the kind, so the tests need it.
func gvkSetter(scheme *runtime.Scheme) func(client.Object, error) error {
	return func(obj client.Object, err error) error {
		if err != nil {
			return err
		}

		gvk, gvkErr := apiutil.GVKForObject(obj, scheme)
		if gvkErr != nil {
			return gvkErr
		}

		obj.GetObjectKind().SetGroupVersionKind(gvk)

		return nil
	}
}

func newTestReconciler(
	t *testing.T,
	manager ProfileManager,
	funcs *interceptor.Funcs,
	objs ...client.Object,
) (*Reconciler, client.Client, *events.FakeRecorder) {
	t.Helper()

	scheme := utiltest.NewScheme(t)

	if funcs == nil {
		funcs = &interceptor.Funcs{}
	}

	setGVK := gvkSetter(scheme)

	if funcs.Get == nil {
		funcs.Get = func(
			ctx context.Context, c client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption,
		) error {
			return setGVK(obj, c.Get(ctx, key, obj, opts...))
		}
	}

	if funcs.Update == nil {
		funcs.Update = func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			return setGVK(obj, c.Update(ctx, obj, opts...))
		}
	}

	if funcs.Patch == nil {
		funcs.Patch = func(
			ctx context.Context, c client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			return setGVK(obj, c.Patch(ctx, obj, patch, opts...))
		}
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(
			&apparmorprofileapi.AppArmorProfile{},
			&secprofnodestatusapi.SecurityProfileNodeStatus{},
		).
		WithInterceptorFuncs(*funcs).
		Build()
	rec := events.NewFakeRecorder(10)

	return &Reconciler{
		client:   cli,
		log:      log.Log,
		record:   rec,
		metrics:  metrics.New(),
		manager:  manager,
		nodeName: testNode,
	}, cli, rec
}

func testRequest() reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: testProfile}}
}

func nodeStatusKey() types.NamespacedName {
	return types.NamespacedName{Name: "apparmorprofile-" + testProfile + "-" + testNode}
}

func getNodeStatus(
	t *testing.T,
	cli client.Client,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	t.Helper()

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	require.NoError(t, cli.Get(t.Context(), nodeStatusKey(), status))

	return status
}

// reconcileUntilInstalled drives a fresh profile through the initial node
// status creation and the installation, which happen in the same reconcile.
func reconcileUntilInstalled(t *testing.T, r *Reconciler) {
	t.Helper()

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
}

func TestReconcileNotSupportedEmitsNodeEvent(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: false}
	r, _, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Zero(t, manager.installs)
	utiltest.RequireEvent(t, rec,
		"Warning AppArmorNotSupportedOnNode node does not support apparmor, profile not added")
}

// A node which installed a profile and lost AppArmor since, like after a
// reboot without it, must not block the deletion of the profile with its
// finalizer.
func TestReconcileNotSupportedReleasesDeletedProfile(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	getNodeStatus(t, cli)

	manager.enabled = false

	require.NoError(t, cli.Delete(t.Context(), testAppArmorProfile()))

	// A failed detection keeps the finalizer, the profile may still be
	// installed.
	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.NoError(
		t,
		cli.Get(t.Context(), testRequest().NamespacedName, &apparmorprofileapi.AppArmorProfile{}),
	)

	manager.unsupported = true

	res, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Zero(t, manager.removes)

	err = cli.Get(t.Context(), testRequest().NamespacedName, &apparmorprofileapi.AppArmorProfile{})
	require.True(t, kerrors.IsNotFound(err), "the profile is gone: %v", err)

	err = cli.Get(t.Context(), nodeStatusKey(), &secprofnodestatusapi.SecurityProfileNodeStatus{})
	require.True(t, kerrors.IsNotFound(err), "the node status is gone: %v", err)
}

// A node known to lack AppArmor marks its node status as unsupported, so that
// the aggregated status of the profiles does not wait for it forever.
func TestReconcileNotSupportedSetsErrorStatus(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{unsupported: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Zero(t, manager.installs)

	status := getNodeStatus(t, cli)
	require.True(t, nodestatus.IsUnsupported(status))
	require.Equal(t, secprofnodestatusapi.ProfileStateError, status.Status.Status)
	require.Equal(t, errNodeWithoutAppArmor.Error(), status.Status.Message)

	// A failed detection does not tell anything about the node.
	manager.unsupported = false
	r2, cli2, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	_, err = r2.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)

	err = cli2.Get(t.Context(), nodeStatusKey(), &secprofnodestatusapi.SecurityProfileNodeStatus{})
	require.True(t, kerrors.IsNotFound(err), "no node status without detection: %v", err)
}

func TestReconcileNotSupportedWithoutRecorder(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestReconciler(t, &countingProfileManager{}, nil)
	r.record = nil

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
}

func TestReconcileGetError(t *testing.T) {
	t.Parallel()

	errGet := errors.New("get failed")
	r, _, _ := newTestReconciler(t, &countingProfileManager{enabled: true}, &interceptor.Funcs{
		Get: func(
			context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption,
		) error {
			return errGet
		},
	})

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errGet)
	require.ErrorIs(t, err, common.ErrGetProfile)
}

func TestReconcileInstallsProfile(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true, updated: true}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	// The first pass creates the node status, finalizer and label, then
	// installs the profile and reports it.
	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	require.Contains(t, profile.GetFinalizers(), util.GetFinalizerNodeString(testNode))
	require.Equal(t, "AppArmorProfile-"+testProfile,
		profile.GetLabels()[secprofnodestatusapi.StatusToProfLabel])
	require.Equal(t, 1, manager.installs)
	require.False(
		t,
		manager.gotOwnedByUs,
		"a pending profile is not vouched for by the node status",
	)

	status := getNodeStatus(t, cli)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, status.Status.Status)
	require.Equal(t, string(secprofnodestatusapi.ProfileStateInstalled),
		status.Labels[secprofnodestatusapi.StatusStateLabel])
	utiltest.RequireEvent(
		t,
		rec,
		"Normal LoadedAppArmorProfile Successfully loaded profile into node "+testNode,
	)

	// Once installed, the node status vouches for the profile and nothing
	// else changes.
	manager.updated = false
	res, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, 2, manager.installs)
	require.True(t, manager.gotOwnedByUs)
	utiltest.RequireNoEvent(t, rec)

	// A changed policy of an installed profile gets loaded again, which is
	// reported although the node status stays installed.
	manager.updated = true
	res, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, 3, manager.installs)
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)
	utiltest.RequireEvent(
		t,
		rec,
		"Normal LoadedAppArmorProfile Successfully loaded profile into node "+testNode,
	)
}

func TestReconcileUnchangedProfileEmitsNoEvent(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true, updated: false}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)

	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)
	utiltest.RequireNoEvent(t, rec)
}

func TestReconcileInstallError(t *testing.T) {
	t.Parallel()

	errInstall := errors.New("apparmor_parser failed")
	manager := &countingProfileManager{enabled: true, installErr: errInstall}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errInstall)
	utiltest.RequireEvent(t, rec, "Warning CannotLoadAppArmorProfile apparmor_parser failed")

	status := getNodeStatus(t, cli)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, status.Status.Status)
	require.Equal(t, errInstall.Error(), status.Status.Message)
	require.Empty(t, status.Annotations[installedAnnotation], "the profile never got installed")
}

// TestReconcileUpdateInstallError asserts that an installed profile whose
// update fails to load reports the error, and that the error status does not
// turn the next attempt into a conflict with a profile of the host.
func TestReconcileUpdateInstallError(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)

	// A status of an earlier release only tells the installation by its
	// state.
	status := getNodeStatus(t, cli)
	delete(status.Annotations, installedAnnotation)
	require.NoError(t, cli.Update(t.Context(), status))

	errInstall := errors.New("apparmor_parser failed")
	manager.installErr = errInstall

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errInstall)
	require.True(t, manager.gotOwnedByUs)
	utiltest.RequireEvent(t, rec, "Warning CannotLoadAppArmorProfile apparmor_parser failed")

	status = getNodeStatus(t, cli)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, status.Status.Status)
	require.Equal(t, "true", status.Annotations[installedAnnotation])

	// The next attempt still owns the profile, and a successful one marks it
	// installed again.
	manager.installErr = nil

	reconcileUntilInstalled(t, r)
	require.True(t, manager.gotOwnedByUs)
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)
}

// TestReconcileRejectsHostProfile asserts that a profile which conflicts with
// a profile of the host is reported once and checked again later, instead of
// being retried with the backoff of the rate limiter.
func TestReconcileRejectsHostProfile(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true, installErr: ErrProfileExists}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	for range 3 {
		res, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{RequeueAfter: rejectedRetry}, res)
	}

	utiltest.RequireEvent(
		t, rec, "Warning CannotLoadAppArmorProfile cannot load profile into node: profile exists",
	)
	utiltest.RequireNoEvent(t, rec)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, getNodeStatus(t, cli).Status.Status)
}

// TestReconcileRejectsHostPolicyFile asserts that a profile whose policy file
// belongs to the host is rejected like a conflict with a loaded profile of the
// host: reported once, with an error node status, and checked again later.
func TestReconcileRejectsHostPolicyFile(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{
		enabled:    true,
		installErr: fmt.Errorf("%w: /etc/apparmor.d/test", ErrHostPolicyFile),
	}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	for range 3 {
		res, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{RequeueAfter: rejectedRetry}, res)
	}

	utiltest.RequireEvent(
		t, rec, "Warning CannotLoadAppArmorProfile cannot load profile into node: "+
			"policy file belongs to the host: /etc/apparmor.d/test",
	)
	utiltest.RequireNoEvent(t, rec)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, getNodeStatus(t, cli).Status.Status)
}

func TestReconcileStatusUpdateError(t *testing.T) {
	t.Parallel()

	errUpdate := errors.New("update failed")
	manager := &countingProfileManager{enabled: true}
	setGVK := gvkSetter(utiltest.NewScheme(t))
	r, _, rec := newTestReconciler(t, manager, &interceptor.Funcs{
		Update: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			if _, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok {
				return errUpdate
			}

			return setGVK(obj, c.Update(ctx, obj, opts...))
		},
	}, testAppArmorProfile())

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errUpdate)
	require.Equal(t, 1, manager.installs)
	utiltest.RequireEvent(
		t,
		rec,
		"Warning CannotUpdateNodeStatus retry function: updating node status annotation: update failed",
	)
}

func TestReconcileSkipsNotReconcilableProfiles(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		modify     func(*apparmorprofileapi.AppArmorProfile)
		wantStatus secprofnodestatusapi.ProfileState
	}{
		{
			name: "disabled",
			modify: func(p *apparmorprofileapi.AppArmorProfile) {
				p.Spec.State = profilebaseapi.SpecStateDisabled
			},
			wantStatus: secprofnodestatusapi.ProfileStateDisabled,
		},
		{
			name: "partial",
			modify: func(p *apparmorprofileapi.AppArmorProfile) {
				p.SetLabels(map[string]string{profilebaseapi.ProfilePartialLabel: "true"})
			},
			wantStatus: secprofnodestatusapi.ProfileStatePartial,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profile := testAppArmorProfile()
			tc.modify(profile)

			manager := &countingProfileManager{enabled: true}
			r, cli, _ := newTestReconciler(t, manager, nil, profile)

			reconcileUntilInstalled(t, r)

			require.Zero(t, manager.installs, "a partial or disabled profile must not be loaded")
			require.Equal(t, tc.wantStatus, getNodeStatus(t, cli).Status.Status)
		})
	}
}

// A profile which got loaded and is disabled afterwards has to be unloaded,
// but only once the pods using it are gone.
func TestReconcileEnabledToDisabled(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true, updated: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	profile.Spec.State = profilebaseapi.SpecStateDisabled
	profile.SetFinalizers(append(profile.GetFinalizers(), util.HasActivePodsFinalizerString))
	require.NoError(t, cli.Update(t.Context(), profile))

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.InUseRetry}, res)
	require.Zero(t, manager.removes, "unloading would unconfine the running pods")
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)

	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	profile.SetFinalizers([]string{util.GetFinalizerNodeString(testNode)})
	require.NoError(t, cli.Update(t.Context(), profile))

	res, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, 1, manager.removes)

	status := getNodeStatus(t, cli)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, status.Status.Status)
	require.Empty(t, status.Annotations[installedAnnotation])

	// Nothing is left to unload afterwards.
	_, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, 1, manager.removes)
}

// A disabled profile installed by a release which did not record the
// installation in the annotation is told to be ours by its installed state,
// without reading back an annotation which the cache may not have yet.
func TestReconcileDisabledInstalledStateWithoutAnnotation(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)

	status := getNodeStatus(t, cli)
	delete(status.Annotations, installedAnnotation)
	require.NoError(t, cli.Update(t.Context(), status))

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	profile.Spec.State = profilebaseapi.SpecStateDisabled
	require.NoError(t, cli.Update(t.Context(), profile))

	_, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, 1, manager.removes)
	require.True(t, manager.removedOwned)
}

func TestReconcileDisabledUnloadError(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true, updated: true}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	<-rec.Events

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	profile.Spec.State = profilebaseapi.SpecStateDisabled
	require.NoError(t, cli.Update(t.Context(), profile))

	manager.removeErr = errors.New("busy")

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorContains(t, err, "busy")
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)
	utiltest.RequireEvent(
		t,
		rec,
		"Warning "+reasonCannotUnloadProfile+" unloading profile from host: busy",
	)
}

func deletingProfile(t *testing.T, cli client.Client) {
	t.Helper()

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	require.NoError(t, cli.Delete(t.Context(), profile))
}

func TestReconcileDeletion(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	deletingProfile(t, cli)

	// The node status turns terminating, then the profile gets unloaded, and
	// the status and finalizer go away.
	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, 1, manager.removes)

	err = cli.Get(t.Context(), nodeStatusKey(), &secprofnodestatusapi.SecurityProfileNodeStatus{})
	require.True(t, kerrors.IsNotFound(err), "node status should be gone, got %v", err)

	err = cli.Get(t.Context(), testRequest().NamespacedName, &apparmorprofileapi.AppArmorProfile{})
	require.True(
		t,
		kerrors.IsNotFound(err),
		"profile should be gone with its last finalizer, got %v",
		err,
	)
}

// A profile installed by a release which did not record the installation in
// the annotation is told to be ours by its installed state, also once a
// failed removal turned the state into terminating.
func TestReconcileDeletionOfInstalledStateWithoutAnnotation(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)

	status := getNodeStatus(t, cli)
	delete(status.Annotations, installedAnnotation)
	require.NoError(t, cli.Update(t.Context(), status))
	deletingProfile(t, cli)

	manager.removeErr = errors.New("busy")

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorContains(t, err, "busy")
	require.True(t, manager.removedOwned)
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateTerminating,
		getNodeStatus(t, cli).Status.Status,
	)

	manager.removeErr = nil
	manager.removedOwned = false

	_, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.True(t, manager.removedOwned)
}

// A foreground deletion removes the owned node statuses before the profile.
// The node must still unload the profile and drop its finalizer.
func TestReconcileDeletionWithoutNodeStatus(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	require.NoError(t, cli.Delete(t.Context(), getNodeStatus(t, cli)))
	deletingProfile(t, cli)

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, 1, manager.removes)

	err = cli.Get(t.Context(), testRequest().NamespacedName, &apparmorprofileapi.AppArmorProfile{})
	require.True(t, kerrors.IsNotFound(err), "profile should be gone, got %v", err)
}

func TestReconcileDeletionWaitsForActivePods(t *testing.T) {
	t.Parallel()

	profile := testAppArmorProfile()
	profile.SetFinalizers([]string{util.HasActivePodsFinalizerString})

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, profile)

	reconcileUntilInstalled(t, r)
	deletingProfile(t, cli)

	for range 2 {
		res, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{RequeueAfter: common.InUseRetry}, res)
	}

	require.Zero(t, manager.removes, "a profile in use by pods must stay loaded")
}

func TestReconcileDeletionRemoveError(t *testing.T) {
	t.Parallel()

	errRemove := errors.New("cannot unload")
	manager := &countingProfileManager{enabled: true, removeErr: errRemove}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	deletingProfile(t, cli)

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errRemove)
	utiltest.RequireEvent(
		t,
		rec,
		"Warning CannotUnloadAppArmorProfile unloading profile from host: cannot unload",
	)

	// The finalizer keeps the profile around for a retry.
	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	require.Contains(t, profile.GetFinalizers(), util.GetFinalizerNodeString(testNode))
}

func TestReconcileWithoutNodeName(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestReconciler(
		t,
		&countingProfileManager{enabled: true},
		nil,
		testAppArmorProfile(),
	)

	r.nodeName = ""

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorContains(t, err, "cannot determine node name")
}

func TestControllerMetadata(t *testing.T) {
	t.Parallel()

	c := NewController()
	require.Equal(t, "apparmor-spod", c.Name())

	scheme := runtime.NewScheme()
	builder := c.SchemeBuilder()
	require.NoError(t, builder.AddToScheme(scheme))
	require.True(t, scheme.Recognizes(apparmorprofileapi.GroupVersion.WithKind("AppArmorProfile")))
}

// Ptrace rules in the paths are deprecated, which is logged once per profile
// and not on every reconcile.
func TestReconcileWarnsAboutDeprecatedPtraceRulesOnce(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		abstract apparmorprofileapi.AppArmorAbstract
		want     int
	}{
		{
			name: "rules in the paths",
			abstract: apparmorprofileapi.AppArmorAbstract{
				Filesystem: &apparmorprofileapi.AppArmorFsRules{
					ReadWritePaths: []string{"ptrace (read),  # ugly template injection hack", "/tmp"},
				},
			},
			want: 1,
		},
		{
			name: "ptrace field",
			abstract: apparmorprofileapi.AppArmorAbstract{
				Ptrace: &apparmorprofileapi.AppArmorPtraceRules{
					AllowedAccess: []apparmorprofileapi.AppArmorPtraceAccess{
						apparmorprofileapi.AppArmorPtraceAccessRead,
					},
				},
			},
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profile := testAppArmorProfile()
			profile.Spec.Abstract = tc.abstract
			r, _, _ := newTestReconciler(t, &countingProfileManager{enabled: true}, nil, profile)

			var (
				mu       sync.Mutex
				warnings int
			)

			r.log = funcr.New(func(_, args string) {
				if strings.Contains(args, "DEPRECATED: ptrace rules") {
					mu.Lock()
					warnings++
					mu.Unlock()
				}
			}, funcr.Options{})

			reconcileUntilInstalled(t, r)

			_, err := r.Reconcile(t.Context(), testRequest())
			require.NoError(t, err)

			mu.Lock()
			defer mu.Unlock()

			require.Equal(t, tc.want, warnings)
		})
	}
}

// A node without AppArmor reports every profile once instead of on every
// reconcile, and again if it got created again under the same name.
func TestReconcileNotSupportedReportsProfileOnce(t *testing.T) {
	t.Parallel()

	const wantEvent = "Warning AppArmorNotSupportedOnNode " +
		"node does not support apparmor, profile not added"

	profile := testAppArmorProfile()
	profile.UID = "first"
	r, cli, rec := newTestReconciler(t, &countingProfileManager{}, nil, profile)

	for range 3 {
		_, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
	}

	utiltest.RequireEvent(t, rec, wantEvent)
	utiltest.RequireNoEvent(t, rec)

	countedErrors := func() float64 {
		t.Helper()

		return utiltest.CounterValue(t, r.metrics.Collectors(),
			"security_profiles_operator_apparmor_profile_error_total",
			map[string]string{"profile": testProfile, "reason": reasonAppArmorNotSupported})
	}
	require.InDelta(t, 1, countedErrors(), 0)

	// The error series of a deleted profile are dropped.
	require.NoError(t, cli.Delete(t.Context(), profile))
	_, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	utiltest.RequireNoEvent(t, rec)
	require.Zero(t, countedErrors())

	recreated := testAppArmorProfile()
	recreated.UID = "second"
	require.NoError(t, cli.Create(t.Context(), recreated))

	for range 2 {
		_, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
	}

	utiltest.RequireEvent(t, rec, wantEvent)
	utiltest.RequireNoEvent(t, rec)
}

// removals returns the number of profile removals counted in the metrics.
func removals(t *testing.T, r *Reconciler) float64 {
	t.Helper()

	return utiltest.CounterValue(t, r.metrics.Collectors(),
		"security_profiles_operator_apparmor_profile_total",
		map[string]string{"operation": "delete"})
}

// deleteUntilGone reconciles the deletion of the profile until it is gone.
func deleteUntilGone(t *testing.T, r *Reconciler, cli client.Client) {
	t.Helper()

	deletingProfile(t, cli)

	for range 2 {
		_, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
	}

	err := cli.Get(t.Context(), testRequest().NamespacedName, &apparmorprofileapi.AppArmorProfile{})
	require.True(t, kerrors.IsNotFound(err), "profile should be gone, got %v", err)
}

// Only a deletion which removed the profile from the host counts as one.
func TestReconcileDeletionCountsRemovedProfiles(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		notRemoved bool
		want       float64
	}{
		{name: "removed", want: 1},
		{name: "nothing to remove", notRemoved: true, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			manager := &countingProfileManager{enabled: true, notRemoved: tc.notRemoved}
			r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

			reconcileUntilInstalled(t, r)
			deleteUntilGone(t, r, cli)

			require.Equal(t, 1, manager.removes)
			require.InDelta(t, tc.want, removals(t, r), 0)
		})
	}
}

// A profile which conflicts with one of the host is reported again once it
// got created again, and the deletion does not count it as removed.
func TestReconcileRejectsRecreatedProfileAgain(t *testing.T) {
	t.Parallel()

	const wantEvent = "Warning CannotLoadAppArmorProfile cannot load profile into node: profile exists"

	profile := testAppArmorProfile()
	profile.UID = "first"

	manager := &countingProfileManager{
		enabled: true, installErr: ErrProfileExists, notRemoved: true,
	}
	r, cli, rec := newTestReconciler(t, manager, nil, profile)

	for range 3 {
		_, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
	}

	utiltest.RequireEvent(t, rec, wantEvent)
	utiltest.RequireNoEvent(t, rec)

	deleteUntilGone(t, r, cli)
	require.Zero(t, removals(t, r))

	_, rejected := r.rejected.Reported(testRequest().NamespacedName)
	require.False(t, rejected, "the conflict of a deleted profile is forgotten")

	recreated := testAppArmorProfile()
	recreated.UID = "second"
	require.NoError(t, cli.Create(t.Context(), recreated))

	for range 2 {
		_, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
	}

	utiltest.RequireEvent(t, rec, wantEvent)
	utiltest.RequireNoEvent(t, rec)
}

// The profiles which got warned about deprecated ptrace rules are forgotten
// once they are gone, and a profile created again gets warned again.
func TestReconcileForgetsPtraceWarningOfDeletedProfile(t *testing.T) {
	t.Parallel()

	profile := testAppArmorProfile()
	profile.UID = "first"
	profile.Spec.Abstract = apparmorprofileapi.AppArmorAbstract{
		Filesystem: &apparmorprofileapi.AppArmorFsRules{
			ReadWritePaths: []string{"ptrace (read),", "/tmp"},
		},
	}

	r, cli, _ := newTestReconciler(t, &countingProfileManager{enabled: true}, nil, profile)

	var (
		mu       sync.Mutex
		warnings int
	)

	r.log = funcr.New(func(_, args string) {
		if strings.Contains(args, "DEPRECATED: ptrace rules") {
			mu.Lock()
			warnings++
			mu.Unlock()
		}
	}, funcr.Options{})

	reconcileUntilInstalled(t, r)
	deleteUntilGone(t, r, cli)

	_, warned := r.ptraceWarned.Reported(testRequest().NamespacedName)
	require.False(t, warned, "the warning about a deleted profile is forgotten")

	recreated := profile.DeepCopy()
	recreated.UID = "second"
	recreated.ResourceVersion = ""
	recreated.Finalizers = nil
	recreated.DeletionTimestamp = nil
	require.NoError(t, cli.Create(t.Context(), recreated))

	reconcileUntilInstalled(t, r)

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, 2, warnings)
}

// The profiles of the operator carry the ownership marker. An AppArmorProfile
// named after one of them must neither replace nor remove it.
func TestReconcileRejectsOperatorProfile(t *testing.T) {
	t.Parallel()

	profile := testAppArmorProfile()
	profile.Name = config.SpoApparmorProfileName

	manager := &countingProfileManager{enabled: true}
	r, cli, rec := newTestReconciler(t, manager, nil, profile)
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: profile.Name}}

	for range 2 {
		res, err := r.Reconcile(t.Context(), req)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res, "a reserved name does not change")
	}

	require.Zero(t, manager.installs)
	utiltest.RequireEvent(t, rec, "Warning CannotLoadAppArmorProfile "+
		"cannot load profile into node: profile name is reserved for the operator")
	utiltest.RequireNoEvent(t, rec)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	require.NoError(t, cli.Get(t.Context(), types.NamespacedName{
		Name: "apparmorprofile-" + profile.Name + "-" + testNode,
	}, status))
	require.Equal(t, secprofnodestatusapi.ProfileStateError, status.Status.Status)

	// An earlier release may have recorded the profile as installed.
	nsc, err := nodestatus.NewForProfileOnNode(profile, cli, testNode)
	require.NoError(t, err)
	require.NoError(t, nsc.SetAnnotation(t.Context(), installedAnnotation, "true"))

	stored := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), req.NamespacedName, stored))
	require.NoError(t, cli.Delete(t.Context(), stored))

	_, err = r.Reconcile(t.Context(), req)
	require.NoError(t, err)
	require.Zero(t, manager.removes, "the profile of the operator must stay")

	err = cli.Get(t.Context(), req.NamespacedName, &apparmorprofileapi.AppArmorProfile{})
	require.True(t, kerrors.IsNotFound(err), "profile should be gone, got %v", err)
}

// A profile whose policy cannot be generated is reported once and shows the
// error in the node status, instead of being retried with every reconcile.
func TestReconcileRejectsInvalidProfile(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{
		enabled:    true,
		installErr: fmt.Errorf("%w: invalid or forbidden capability: \"foo\"", ErrInvalidProfile),
	}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	for range 3 {
		res, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res, "only a change of the profile fixes it")
	}

	utiltest.RequireEvent(t, rec, "Warning CannotLoadAppArmorProfile cannot load profile "+
		"into node: invalid profile: invalid or forbidden capability: \"foo\"")
	utiltest.RequireNoEvent(t, rec)

	status := getNodeStatus(t, cli)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, status.Status.Status)
	require.Contains(t, status.Status.Message, "invalid or forbidden capability")
}

// The error series of a profile are dropped once the profile is gone.
func TestReconcileDeletesErrorSeriesOfGoneProfile(t *testing.T) {
	t.Parallel()

	manager := &countingProfileManager{enabled: true, installErr: errors.New("failed")}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	countedErrors := func() float64 {
		t.Helper()

		return utiltest.CounterValue(t, r.metrics.Collectors(),
			"security_profiles_operator_apparmor_profile_error_total",
			map[string]string{"profile": testProfile, "reason": reasonCannotLoadProfile})
	}

	_, err := r.Reconcile(t.Context(), testRequest())
	require.Error(t, err)
	require.InDelta(t, 1, countedErrors(), 0)

	manager.installErr = nil

	reconcileUntilInstalled(t, r)
	deleteUntilGone(t, r, cli)

	require.Zero(t, countedErrors())
}

// A disabled profile which this node never loaded has nothing to unload, so
// pods using it on other nodes do not keep it from being disabled here.
func TestReconcileDisabledNotInstalledInUse(t *testing.T) {
	t.Parallel()

	profile := testAppArmorProfile()
	profile.Spec.State = profilebaseapi.SpecStateDisabled
	profile.SetFinalizers([]string{util.HasActivePodsFinalizerString})

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, profile)

	nsc, err := nodestatus.NewForProfileOnNode(profile, cli, testNode)
	require.NoError(t, err)
	_, err = nsc.Create(t.Context())
	require.NoError(t, err)
	require.NoError(t, nsc.SetNodeStatus(t.Context(), secprofnodestatusapi.ProfileStateError))

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Zero(t, manager.removes)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, getNodeStatus(t, cli).Status.Status)
}

// A profile which got loaded while the record of its installation failed is
// unloaded once it gets disabled, which the ownership marker of its policy
// file tells.
func TestReconcileDisabledLoadedWithoutRecord(t *testing.T) {
	t.Parallel()

	profile := testAppArmorProfile()
	profile.Spec.State = profilebaseapi.SpecStateDisabled

	manager := &countingProfileManager{enabled: true, loaded: true}
	r, cli, _ := newTestReconciler(t, manager, nil, profile)

	nsc, err := nodestatus.NewForProfileOnNode(profile, cli, testNode)
	require.NoError(t, err)
	_, err = nsc.Create(t.Context())
	require.NoError(t, err)
	require.NoError(t, nsc.SetNodeStatus(t.Context(), secprofnodestatusapi.ProfileStatePending))

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, 1, manager.removes)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, getNodeStatus(t, cli).Status.Status)
}
