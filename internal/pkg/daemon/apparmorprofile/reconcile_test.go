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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	testNode    = "test-node"
	testProfile = "test-profile"
)

// countingProfileManager is a ProfileManager that records how the reconciler
// drives it.
type countingProfileManager struct {
	enabled    bool
	updated    bool
	installErr error
	removeErr  error

	installs     int
	removes      int
	gotOwnedByUs bool
}

func (m *countingProfileManager) Enabled() bool {
	return m.enabled
}

func (m *countingProfileManager) InstallProfile(
	_ profilebaseapi.StatusBaseUser, ownedByUs bool,
) (bool, error) {
	m.installs++
	m.gotOwnedByUs = ownedByUs

	return m.updated, m.installErr
}

func (m *countingProfileManager) RemoveProfile(profilebaseapi.StatusBaseUser, bool) error {
	m.removes++

	return m.removeErr
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, apparmorprofileapi.AddToScheme(scheme))
	require.NoError(t, secprofnodestatusapi.AddToScheme(scheme))

	return scheme
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

	scheme := testScheme(t)

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
		client:  cli,
		log:     log.Log,
		record:  rec,
		metrics: metrics.New(),
		manager: manager,
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

func requireNoEvent(t *testing.T, rec *events.FakeRecorder) {
	t.Helper()

	select {
	case event := <-rec.Events:
		require.Failf(t, "unexpected event", "%s", event)
	default:
	}
}

func requireEvent(t *testing.T, rec *events.FakeRecorder, want string) {
	t.Helper()

	select {
	case event := <-rec.Events:
		require.Equal(t, want, event)
	default:
		require.Failf(t, "missing event", "%s", want)
	}
}

// reconcileUntilInstalled drives a fresh profile through the initial node
// status creation and the installation.
func reconcileUntilInstalled(t *testing.T, r *Reconciler) {
	t.Helper()

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)

	res, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
}

func TestReconcileNotSupportedEmitsNodeEvent(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	manager := &countingProfileManager{enabled: false}
	r, _, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Zero(t, manager.installs)
	requireEvent(t, rec,
		"Warning AppArmorNotSupportedOnNode node does not support apparmor, profile not added")
}

func TestReconcileNotSupportedWithoutRecorder(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	r, _, _ := newTestReconciler(t, &countingProfileManager{}, nil)
	r.record = nil

	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
}

func TestReconcileGetError(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

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
	require.ErrorContains(t, err, common.ErrGetProfile)
}

func TestReconcileInstallsProfile(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	manager := &countingProfileManager{enabled: true, updated: true}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	// The first pass only creates the node status, finalizer and label.
	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	require.Zero(t, manager.installs)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, getNodeStatus(t, cli).Status.Status)

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	require.Contains(t, profile.GetFinalizers(), util.GetFinalizerNodeString(testNode))
	require.Equal(t, "AppArmorProfile-"+testProfile,
		profile.GetLabels()[secprofnodestatusapi.StatusToProfLabel])

	// The second pass installs the profile and reports it.
	res, err = r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
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
	requireEvent(
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
	requireNoEvent(t, rec)
}

func TestReconcileUnchangedProfileEmitsNoEvent(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	manager := &countingProfileManager{enabled: true, updated: false}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)

	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateInstalled,
		getNodeStatus(t, cli).Status.Status,
	)
	requireNoEvent(t, rec)
}

func TestReconcileInstallError(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	errInstall := errors.New("apparmor_parser failed")
	manager := &countingProfileManager{enabled: true, installErr: errInstall}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	_, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)

	_, err = r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errInstall)
	requireEvent(t, rec, "Warning CannotLoadAppArmorProfile apparmor_parser failed")
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, getNodeStatus(t, cli).Status.Status)
}

func TestReconcileStatusUpdateError(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	errUpdate := errors.New("update failed")
	manager := &countingProfileManager{enabled: true}
	failUpdates := false
	setGVK := gvkSetter(testScheme(t))
	r, _, rec := newTestReconciler(t, manager, &interceptor.Funcs{
		Update: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			if _, ok := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); ok && failUpdates {
				return errUpdate
			}

			return setGVK(obj, c.Update(ctx, obj, opts...))
		},
	}, testAppArmorProfile())

	_, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)

	failUpdates = true
	_, err = r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errUpdate)
	require.Equal(t, 1, manager.installs)
	requireEvent(
		t,
		rec,
		"Warning CannotUpdateNodeStatus updating node status annotation: update failed",
	)
}

func TestReconcileSkipsNotReconcilableProfiles(t *testing.T) {
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
			t.Setenv(config.NodeNameEnvKey, testNode)

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

func deletingProfile(t *testing.T, cli client.Client) {
	t.Helper()

	profile := &apparmorprofileapi.AppArmorProfile{}
	require.NoError(t, cli.Get(t.Context(), testRequest().NamespacedName, profile))
	require.NoError(t, cli.Delete(t.Context(), profile))
}

func TestReconcileDeletion(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	deletingProfile(t, cli)

	// The node status turns terminating first.
	res, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	require.Zero(t, manager.removes)
	require.Equal(
		t,
		secprofnodestatusapi.ProfileStateTerminating,
		getNodeStatus(t, cli).Status.Status,
	)

	// Then the profile gets unloaded, and the status and finalizer go away.
	res, err = r.Reconcile(t.Context(), testRequest())
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

func TestReconcileDeletionWaitsForActivePods(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	profile := testAppArmorProfile()
	profile.SetFinalizers([]string{util.HasActivePodsFinalizerString})

	manager := &countingProfileManager{enabled: true}
	r, cli, _ := newTestReconciler(t, manager, nil, profile)

	reconcileUntilInstalled(t, r)
	deletingProfile(t, cli)

	for range 2 {
		res, err := r.Reconcile(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	}

	require.Zero(t, manager.removes, "a profile in use by pods must stay loaded")
}

func TestReconcileDeletionRemoveError(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, testNode)

	errRemove := errors.New("cannot unload")
	manager := &countingProfileManager{enabled: true, removeErr: errRemove}
	r, cli, rec := newTestReconciler(t, manager, nil, testAppArmorProfile())

	reconcileUntilInstalled(t, r)
	deletingProfile(t, cli)

	_, err := r.Reconcile(t.Context(), testRequest())
	require.NoError(t, err)

	_, err = r.Reconcile(t.Context(), testRequest())
	require.ErrorIs(t, err, errRemove)
	requireEvent(
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
	// NewForProfile checks presence, not content, so unset the variable.
	t.Setenv(config.NodeNameEnvKey, "")
	require.NoError(t, os.Unsetenv(config.NodeNameEnvKey))

	r, _, _ := newTestReconciler(
		t,
		&countingProfileManager{enabled: true},
		nil,
		testAppArmorProfile(),
	)

	_, err := r.Reconcile(t.Context(), testRequest())
	require.ErrorContains(t, err, "cannot determine node name")
}

func TestReconcileAppArmorProfileNil(t *testing.T) {
	t.Parallel()

	r := &Reconciler{}
	_, err := r.reconcileAppArmorProfile(t.Context(), nil, log.Log)
	require.EqualError(t, err, errAppArmorProfileNil)
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	r := &Reconciler{manager: &countingProfileManager{enabled: true}}
	require.NoError(t, r.Healthz(nil))

	r.manager = &countingProfileManager{enabled: false}
	require.ErrorContains(t, r.Healthz(nil), "does not support apparmor")
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

func TestOk(t *testing.T) {
	t.Parallel()

	require.Equal(t, "OK", ok(true, nil))
	require.Equal(t, "NOT OK (boom)", ok(false, errors.New("boom")))
}
