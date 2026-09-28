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

package seccompprofile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile/seccompprofilefakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	testNode      = "test-node"
	testNamespace = "test-ns"
	testProfile   = "test-profile"
)

var testProfileKey = types.NamespacedName{Namespace: testNamespace, Name: testProfile}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))
	require.NoError(t, secprofnodestatusapi.AddToScheme(scheme))
	require.NoError(t, spodapi.AddToScheme(scheme))

	return scheme
}

func newTestProfile() *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: seccompprofileapi.GroupVersion.String(),
			Kind:       "SeccompProfile",
		},
		ObjectMeta: metav1.ObjectMeta{Name: testProfile, Namespace: testNamespace},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActErrno,
			Syscalls: []seccompprofileapi.Syscall{{
				Action: seccompprofileapi.ActAllow,
				Names:  []string{"read", "write"},
			}},
		},
	}
}

type savedProfile struct {
	path    string
	content []byte
}

type reconcileEnv struct {
	rec      *Reconciler
	cli      client.Client
	recorder *events.FakeRecorder
	impl     *seccompprofilefakes.FakeImpl
	saved    []savedProfile
	saveErr  error
	updated  bool
}

// newReconcileEnv sets up a reconciler with a fake API server containing the
// given objects.
func newReconcileEnv(t *testing.T, objs ...client.Object) *reconcileEnv {
	t.Helper()

	scheme := testScheme(t)

	// The node status name and labels are derived from the kind of the
	// profile object. The fake client clears the TypeMeta of typed objects
	// on every call, so restore it like the informer cache does on reads.
	keepGVK := func(obj client.Object) error {
		gvk, err := apiutil.GVKForObject(obj, scheme)
		if err != nil {
			return err
		}

		obj.GetObjectKind().SetGroupVersionKind(gvk)

		return nil
	}

	env := &reconcileEnv{
		cli: fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(objs...).
			WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
			WithIndex(&seccompprofileapi.SeccompProfile{}, baseProfileIndex, indexBaseProfile).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(
					ctx context.Context, c client.WithWatch, key client.ObjectKey,
					obj client.Object, opts ...client.GetOption,
				) error {
					if err := c.Get(ctx, key, obj, opts...); err != nil {
						return err
					}

					return keepGVK(obj)
				},
				Update: func(
					ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
				) error {
					if err := c.Update(ctx, obj, opts...); err != nil {
						return err
					}

					return keepGVK(obj)
				},
			}).
			Build(),
		recorder: events.NewFakeRecorder(10),
		impl:     &seccompprofilefakes.FakeImpl{},
		updated:  true,
	}
	env.impl.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)

	env.rec = &Reconciler{
		impl:     env.impl,
		client:   env.cli,
		log:      log.Log,
		record:   env.recorder,
		metrics:  metrics.New(),
		nodeName: testNode,
		save: func(p string, c []byte) (bool, error) {
			if env.saveErr != nil {
				return false, env.saveErr
			}

			env.saved = append(env.saved, savedProfile{path: p, content: c})

			return env.updated, nil
		},
	}

	return env
}

// reconcile runs the reconciler on the current state of the test profile, the
// way the controller would after fetching it.
func (e *reconcileEnv) reconcile(t *testing.T) (reconcile.Result, error) {
	t.Helper()

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, e.cli.Get(t.Context(), testProfileKey, sp))

	return e.rec.reconcileSeccompProfile(t.Context(), sp, log.Log)
}

func (e *reconcileEnv) nodeStatus(t *testing.T) *secprofnodestatusapi.SecurityProfileNodeStatus {
	t.Helper()

	list := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	require.NoError(t, e.cli.List(t.Context(), list, client.InNamespace(testNamespace)))

	if len(list.Items) == 0 {
		return nil
	}

	require.Len(t, list.Items, 1)

	return &list.Items[0]
}

func (e *reconcileEnv) events() []string {
	var res []string

	for {
		select {
		case ev := <-e.recorder.Events:
			res = append(res, ev)
		default:
			return res
		}
	}
}

func TestReconcileSeccompProfileNil(t *testing.T) {
	t.Parallel()

	r := &Reconciler{}
	_, err := r.reconcileSeccompProfile(t.Context(), nil, log.Log)
	require.ErrorIs(t, err, errSeccompProfileNil)
}

func TestReconcileSeccompProfileInstall(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())

	// The first pass only registers the node: finalizer, label and a
	// pending node status, then requeues without touching the disk.
	res, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	require.Empty(t, env.saved)

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	require.Contains(t, sp.GetFinalizers(), util.GetFinalizerNodeString(testNode))
	require.Equal(t,
		"SeccompProfile-"+testProfile,
		sp.GetLabels()[secprofnodestatusapi.StatusToProfLabel],
	)

	status := env.nodeStatus(t)
	require.NotNil(t, status)
	require.Equal(t, testNode, status.Spec.NodeName)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, status.Status.Status)
	require.Len(t, status.GetOwnerReferences(), 1)
	require.Equal(t, testProfile, status.GetOwnerReferences()[0].Name)

	// The second pass writes the profile and marks the node as installed.
	res, err = env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	require.JSONEq(t,
		`[{"names":["read","write"],"action":"SCMP_ACT_ALLOW"}]`,
		sp.GetAnnotations()[syscallsAnnotation],
	)

	require.Len(t, env.saved, 1)
	require.Equal(t, sp.GetProfilePath(), env.saved[0].path)

	var spec seccompprofileapi.SeccompProfileSpec
	require.NoError(t, json.Unmarshal(env.saved[0].content, &spec))
	require.Equal(t, seccompprofileapi.ActErrno, spec.DefaultAction)
	require.Equal(t, []string{"read", "write"}, spec.Syscalls[0].Names)

	evs := env.events()
	require.Len(t, evs, 1)
	require.True(t, strings.HasPrefix(evs[0], "Normal "+reasonSavedProfile+" "), evs[0])
	require.Contains(t, evs[0], testNode)

	status = env.nodeStatus(t)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, status.Status.Status)
	require.Equal(t,
		string(secprofnodestatusapi.ProfileStateInstalled),
		status.GetLabels()[secprofnodestatusapi.StatusStateLabel],
	)

	// An unchanged profile on disk is neither reported nor reinstalled.
	env.updated = false
	res, err = env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Empty(t, env.events())
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.nodeStatus(t).Status.Status)
}

func TestReconcileSeccompProfileDisabled(t *testing.T) {
	t.Parallel()

	sp := newTestProfile()
	sp.Spec.State = profilebaseapi.SpecStateDisabled
	env := newReconcileEnv(t, sp)

	_, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, env.nodeStatus(t).Status.Status)

	// A disabled profile is never written to the node.
	res, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Empty(t, env.saved)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, env.nodeStatus(t).Status.Status)
}

func TestReconcileSeccompProfileSaveError(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())

	_, err := env.reconcile(t)
	require.NoError(t, err)

	env.saveErr = errors.New("disk full")
	_, err = env.reconcile(t)
	require.ErrorContains(t, err, "disk full")

	evs := env.events()
	require.Len(t, evs, 1)
	require.Equal(t, "Warning "+reasonCannotSaveProfile+" disk full", evs[0])

	// The node must not claim the profile is installed.
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, env.nodeStatus(t).Status.Status)
}

func TestReconcileSeccompProfileNotAllowed(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())
	env.impl.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}},
		},
	}, nil)

	_, err := env.reconcile(t)
	require.NoError(t, err)

	// A rejected profile is not retried until it or the SPOD changes, which
	// both trigger a reconcile.
	res, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	evs := env.events()
	require.Len(t, evs, 1)
	require.True(t, strings.HasPrefix(evs[0], "Warning "+reasonProfileNotAllowed+" "), evs[0])
	require.Contains(t, evs[0], "syscall not allowed: write")

	// Rejected profiles show the error and do not get a file on disk.
	require.Equal(t, secprofnodestatusapi.ProfileStateError, env.nodeStatus(t).Status.Status)
	require.Empty(t, env.saved)
}

func TestReconcileSeccompProfileGetSPODError(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())
	env.impl.GetSPODReturns(nil, errors.New("no spod"))

	_, err := env.reconcile(t)
	require.NoError(t, err)

	// A failure of the API server is retried with backoff.
	_, err = env.reconcile(t)
	require.ErrorContains(t, err, "retrieving the SPOD configuration: no spod")
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, env.nodeStatus(t).Status.Status)
	require.Empty(t, env.saved)
}

func TestReconcileSeccompProfileMergeError(t *testing.T) {
	t.Parallel()

	sp := newTestProfile()
	sp.Spec.BaseProfileName = "missing"
	env := newReconcileEnv(t, sp)
	env.impl.ClientGetProfileReturns(nil, errors.New("api down"))

	_, err := env.reconcile(t)
	require.NoError(t, err)

	// A base profile which cannot be looked up is retried with backoff.
	_, err = env.reconcile(t)
	require.ErrorContains(t, err, "api down")
	require.Empty(t, env.events())
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, env.nodeStatus(t).Status.Status)

	// A missing base profile is shown and not retried: the profile gets
	// enqueued once the base profile is created.
	env.impl.ClientGetProfileReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, "missing"))

	res, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	evs := env.events()
	require.Len(t, evs, 1)
	require.True(t, strings.HasPrefix(evs[0], "Warning "+reasonInvalidSeccompProfile+" "), evs[0])
	require.Contains(t, evs[0], "missing not found")
	require.Equal(t, secprofnodestatusapi.ProfileStateError, env.nodeStatus(t).Status.Status)
	require.Empty(t, env.saved)
}

func TestDerivedProfileRequests(t *testing.T) {
	t.Parallel()

	base := newTestProfile()
	base.Name = "base"

	derived := newTestProfile()
	derived.Name = "derived"
	derived.Spec.BaseProfileName = "base"

	// Profiles further down the chain have to be enqueued as well, and a
	// cycle must not loop.
	derivedTwice := newTestProfile()
	derivedTwice.Name = "derived-twice"
	derivedTwice.Spec.BaseProfileName = "derived"

	cycle := newTestProfile()
	cycle.Name = "cycle"
	cycle.Spec.BaseProfileName = "derived-twice"

	base.Spec.BaseProfileName = "cycle"

	other := newTestProfile()
	other.Name = "other"
	other.Spec.BaseProfileName = "another"

	env := newReconcileEnv(t, base, derived, derivedTwice, cycle, other)

	reqs := env.rec.derivedProfileRequests(t.Context(), base)
	require.Equal(t, []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: "derived"}},
		{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: "derived-twice"}},
		{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: "cycle"}},
	}, reqs)
}

// A profile which got installed and is disabled afterwards has to be removed
// from the node.
func TestReconcileSeccompProfileEnabledToDisabled(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())
	env.rec.profileRoot = t.TempDir()
	env.rec.save = saveProfileOnDisk

	for range 2 {
		_, err := env.reconcile(t)
		require.NoError(t, err)
	}

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))

	profilePath := env.rec.profilePath(sp)
	require.FileExists(t, profilePath)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.nodeStatus(t).Status.Status)

	// Pods still use the profile, so it stays until they are gone.
	sp.Spec.State = profilebaseapi.SpecStateDisabled
	sp.SetFinalizers(append(sp.GetFinalizers(), util.HasActivePodsFinalizerString))
	require.NoError(t, env.cli.Update(t.Context(), sp))

	res, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.InUseRetry}, res)
	require.FileExists(t, profilePath)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.nodeStatus(t).Status.Status)

	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	sp.SetFinalizers([]string{util.GetFinalizerNodeString(testNode)})
	require.NoError(t, env.cli.Update(t.Context(), sp))

	res, err = env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.NoFileExists(t, profilePath)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, env.nodeStatus(t).Status.Status)

	// Enabling it again installs it again.
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	sp.Spec.State = profilebaseapi.SpecStateEnabled
	require.NoError(t, env.cli.Update(t.Context(), sp))

	_, err = env.reconcile(t)
	require.NoError(t, err)
	require.FileExists(t, profilePath)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.nodeStatus(t).Status.Status)
}

// A disabled profile which shares its file with an installed profile must not
// remove the file of the other profile.
func TestReconcileSeccompProfileDisabledKeepsFileOfOtherProfile(t *testing.T) {
	t.Parallel()

	disabled := newTestProfile()
	disabled.CreationTimestamp = metav1.Unix(100, 0)
	disabled.Spec.State = profilebaseapi.SpecStateDisabled

	owner := newTestProfile()
	owner.Name = testProfile + seccompprofileapi.ExtJSON
	owner.CreationTimestamp = metav1.Unix(200, 0)

	env := newReconcileEnv(t, disabled, owner)
	env.rec.profileRoot = t.TempDir()

	ownerFile := env.rec.profilePath(owner)
	require.NoError(t, os.WriteFile(ownerFile, []byte("owner"), 0o600))

	_, err := env.reconcile(t)
	require.NoError(t, err)

	// Pretend the profile got installed before it was disabled.
	stored := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, stored))
	ns, err := nodestatus.NewForProfileOnNode(stored, env.cli, testNode)
	require.NoError(t, err)
	require.NoError(t, ns.SetNodeStatus(t.Context(), secprofnodestatusapi.ProfileStateInstalled))

	_, err = env.reconcile(t)
	require.NoError(t, err)
	require.FileExists(t, ownerFile)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, env.nodeStatus(t).Status.Status)
}

// Nodes of different architectures resolve OCI base profiles differently, so
// each architecture writes its own annotation instead of fighting over one.
func TestAnnotateSyscallsPerArchitecture(t *testing.T) {
	t.Parallel()

	sp := newTestProfile()
	sp.Annotations = map[string]string{
		// Written by a version which put every result into it.
		syscallsAnnotation: "stale",
		// Written by a node of another architecture.
		"syscalls-otherarch": "other",
	}
	env := newReconcileEnv(t, sp)

	syscalls := []seccompprofileapi.Syscall{
		{Names: []string{"read"}, Action: seccompprofileapi.ActAllow},
	}
	archKey := syscallsAnnotationKey(true)
	require.Equal(t, syscallsAnnotation+"-"+goruntime.GOARCH, archKey)

	stored := func() *seccompprofileapi.SeccompProfile {
		got := &seccompprofileapi.SeccompProfile{}
		require.NoError(t, env.cli.Get(t.Context(), testProfileKey, got))

		return got
	}

	require.NoError(t, env.rec.annotateSyscalls(t.Context(), stored(), syscalls, true, log.Log))

	got := stored()
	require.JSONEq(t, `[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]`, got.Annotations[archKey])
	require.NotContains(t, got.Annotations, syscallsAnnotation,
		"the shared annotation would flap between the architectures")
	require.Equal(t, "other", got.Annotations["syscalls-otherarch"])

	// An unchanged result is not written again.
	rv := got.GetResourceVersion()
	require.NoError(t, env.rec.annotateSyscalls(t.Context(), got, syscalls, true, log.Log))
	require.Equal(t, rv, stored().GetResourceVersion())

	// Without an OCI base profile the result is the same everywhere.
	require.NoError(t, env.rec.annotateSyscalls(t.Context(), stored(), syscalls, false, log.Log))

	got = stored()
	require.Contains(t, got.Annotations, syscallsAnnotation)
	require.NotContains(t, got.Annotations, archKey)
}

func TestReconcileSeccompProfileDeletion(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())

	for range 2 {
		_, err := env.reconcile(t)
		require.NoError(t, err)
	}

	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.nodeStatus(t).Status.Status)

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	require.NoError(t, env.cli.Delete(t.Context(), sp))

	// The node status first goes to terminating.
	res, err := env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, env.nodeStatus(t).Status.Status)

	// Then the node removes its finalizer and status, which lets the API
	// server delete the profile.
	res, err = env.reconcile(t)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Nil(t, env.nodeStatus(t))

	err = env.cli.Get(t.Context(), testProfileKey, sp)
	require.True(t, kerrors.IsNotFound(err), "profile should be gone, got %v", err)
}

// A profile named "foo.json" is stored in the same file as a profile named
// "foo". The later one must not overwrite the file of the earlier one.
func TestReconcileSeccompProfileFileConflict(t *testing.T) {
	t.Parallel()

	owner := newTestProfile()
	owner.CreationTimestamp = metav1.Unix(100, 0)

	conflicting := newTestProfile()
	conflicting.Name = testProfile + seccompprofileapi.ExtJSON
	conflicting.CreationTimestamp = metav1.Unix(200, 0)

	env := newReconcileEnv(t, owner, conflicting)
	key := types.NamespacedName{Namespace: testNamespace, Name: conflicting.Name}

	reconcileConflicting := func() (reconcile.Result, error) {
		sp := &seccompprofileapi.SeccompProfile{}
		require.NoError(t, env.cli.Get(t.Context(), key, sp))

		return env.rec.reconcileSeccompProfile(t.Context(), sp, log.Log)
	}

	_, err := reconcileConflicting()
	require.NoError(t, err)

	res, err := reconcileConflicting()
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: fileConflictRetry}, res)
	require.Empty(t, env.saved, "the file of the other profile must not be overwritten")
	require.Equal(t, secprofnodestatusapi.ProfileStateError, env.nodeStatus(t).Status.Status)

	gotEvents := env.events()
	require.Len(t, gotEvents, 1)
	require.Contains(t, gotEvents[0], "Warning "+reasonProfileFileConflict)
	require.Contains(t, gotEvents[0],
		conflicting.Name+" is stored as "+conflicting.Name+" like "+testProfile)

	// The owner is unaffected by the later profile.
	other, err := fileOwner(t.Context(), env.rec.apiReader(), owner)
	require.NoError(t, err)
	require.Empty(t, other)

	// Deleting the later profile keeps the file of the owner.
	env.rec.profileRoot = t.TempDir()
	ownerFile := env.rec.profilePath(owner)
	require.NoError(t, os.WriteFile(ownerFile, []byte("owner"), 0o600))

	require.NoError(t, env.rec.handleDeletion(t.Context(), conflicting))

	content, err := os.ReadFile(ownerFile)
	require.NoError(t, err)
	require.Equal(t, "owner", string(content))

	// Once the owner goes away, the later profile takes the file over, so
	// deleting the owner keeps it as well.
	storedOwner := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, storedOwner))

	now := metav1.Now()
	storedOwner.DeletionTimestamp = &now
	require.NoError(t, env.rec.handleDeletion(t.Context(), storedOwner))
	require.FileExists(t, ownerFile)
}

func TestFileOwnerSkipsInactiveOwners(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		mutateOwner func(*seccompprofileapi.SeccompProfile)
		wantOwner   bool
	}{
		"active owner": {wantOwner: true},
		"disabled owner": {
			mutateOwner: func(sp *seccompprofileapi.SeccompProfile) { sp.Spec.State = profilebaseapi.SpecStateDisabled },
		},
		"partial owner": {
			mutateOwner: func(sp *seccompprofileapi.SeccompProfile) {
				sp.Labels = map[string]string{profilebaseapi.ProfilePartialLabel: "true"}
			},
		},
		"owner being deleted": {
			mutateOwner: func(sp *seccompprofileapi.SeccompProfile) {
				now := metav1.Now()
				sp.DeletionTimestamp = &now
				sp.Finalizers = []string{"test"}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			owner := newTestProfile()
			owner.CreationTimestamp = metav1.Unix(100, 0)

			if tc.mutateOwner != nil {
				tc.mutateOwner(owner)
			}

			later := newTestProfile()
			later.Name = testProfile + seccompprofileapi.ExtJSON
			later.CreationTimestamp = metav1.Unix(200, 0)

			env := newReconcileEnv(t, owner, later)

			got, err := fileOwner(t.Context(), env.rec.apiReader(), later)
			require.NoError(t, err)

			if tc.wantOwner {
				require.Equal(t, testProfile, got)
			} else {
				require.Empty(t, got)
			}
		})
	}
}

// The ownership is decided with the API server, not with a cache which may
// not know the other profile yet.
func TestFileOwnerReadsFromAPIServer(t *testing.T) {
	t.Parallel()

	owner := newTestProfile()
	owner.CreationTimestamp = metav1.Unix(100, 0)

	later := newTestProfile()
	later.Name = testProfile + seccompprofileapi.ExtJSON
	later.CreationTimestamp = metav1.Unix(200, 0)

	env := newReconcileEnv(t, later)
	env.rec.reader = newReconcileEnv(t, owner, later).cli

	got, err := fileOwner(t.Context(), env.rec.apiReader(), later)
	require.NoError(t, err)
	require.Equal(t, testProfile, got)
}

func TestSiblingRequests(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]string{
		"foo":      "foo.json",
		"foo.json": "foo",
	} {
		requests := siblingRequests(t.Context(), &seccompprofileapi.SeccompProfile{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		})
		require.Equal(
			t,
			[]reconcile.Request{{NamespacedName: types.NamespacedName{Name: want}}},
			requests,
		)
	}

	require.Empty(t, siblingRequests(t.Context(), &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: ".json"},
	}))
}

func TestOwnsFileBefore(t *testing.T) {
	t.Parallel()

	older := &seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{
		Name: "b", CreationTimestamp: metav1.Unix(1, 0),
	}}
	newer := &seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{
		Name: "a", CreationTimestamp: metav1.Unix(2, 0),
	}}
	sameTime := &seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{
		Name: "c", CreationTimestamp: metav1.Unix(1, 0),
	}}

	require.True(t, ownsFileBefore(older, newer))
	require.False(t, ownsFileBefore(newer, older))
	require.True(t, ownsFileBefore(older, sameTime), "the name decides on a tie")
	require.False(t, ownsFileBefore(sameTime, older))
}

func TestReconcileSeccompProfileDeletionInUse(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())

	for range 2 {
		_, err := env.reconcile(t)
		require.NoError(t, err)
	}

	sp := &seccompprofileapi.SeccompProfile{}
	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	sp.SetFinalizers(append(sp.GetFinalizers(), util.HasActivePodsFinalizerString))
	require.NoError(t, env.cli.Update(t.Context(), sp))
	require.NoError(t, env.cli.Delete(t.Context(), sp))

	// Terminating first, then waiting for the pods to go away.
	for range 3 {
		res, err := env.reconcile(t)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	}

	require.NoError(t, env.cli.Get(t.Context(), testProfileKey, sp))
	require.Contains(t, sp.GetFinalizers(), util.GetFinalizerNodeString(testNode))
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, env.nodeStatus(t).Status.Status)
}

func TestHandleAllowedSyscallsChanged(t *testing.T) {
	t.Parallel()

	allowed := newTestProfile()
	allowed.Name = "allowed"
	allowed.Spec.Syscalls[0].Names = []string{"read"}

	forbidden := newTestProfile()
	forbidden.Name = "forbidden"

	spod := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}},
		},
	}

	invalidSPOD := spod.DeepCopy()
	invalidSPOD.Spec.Security.AllowedSeccompActions = []seccompprofileapi.Action{
		seccompprofileapi.ActErrno,
	}

	for _, tc := range []struct {
		name         string
		obj          client.Object
		wantRequests []string
		wantDeleted  []string
		wantEvent    string
	}{
		{
			name:         "deletes profiles using forbidden syscalls",
			obj:          spod,
			wantRequests: []string{"allowed", "forbidden"},
			wantDeleted:  []string{"forbidden"},
		},
		{
			name:         "checks all profiles again for an empty allow list",
			obj:          &spodapi.SecurityProfilesOperatorDaemon{},
			wantRequests: []string{"allowed", "forbidden"},
		},
		{
			name:         "never deletes profiles because of an invalid action",
			obj:          invalidSPOD,
			wantRequests: []string{"allowed", "forbidden"},
			wantEvent:    "Warning " + reasonInvalidSPODConfig,
		},
		{
			name:         "ignores other objects",
			obj:          allowed.DeepCopy(),
			wantRequests: []string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cli := fake.NewClientBuilder().
				WithScheme(testScheme(t)).
				WithObjects(allowed.DeepCopy(), forbidden.DeepCopy()).
				Build()
			recorder := events.NewFakeRecorder(10)
			r := &Reconciler{client: cli, log: log.Log, record: recorder}

			reqs := r.handleAllowedSyscallsChanged(t.Context(), tc.obj)

			got := make([]string, 0, len(reqs))
			for _, req := range reqs {
				got = append(got, req.Name)
			}

			require.Equal(t, tc.wantRequests, got)

			list := &seccompprofileapi.SeccompProfileList{}
			require.NoError(t, cli.List(t.Context(), list))
			require.Len(t, list.Items, 2-len(tc.wantDeleted))

			for _, sp := range list.Items {
				require.NotContains(t, tc.wantDeleted, sp.Name)
			}

			if tc.wantEvent == "" {
				require.Empty(t, recorder.Events)
			} else {
				require.Len(t, recorder.Events, 1)
				require.Contains(t, <-recorder.Events, tc.wantEvent)
			}
		})
	}
}

// Every node handles the SPOD change and deletes the same profiles, so a
// profile which another node deleted already is not an error.
func TestHandleAllowedSyscallsChangedToleratesDeletedProfile(t *testing.T) {
	t.Parallel()

	forbidden := newTestProfile()
	forbidden.Name = "forbidden"

	deletes := 0
	cli := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(forbidden).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(
				context.Context, client.WithWatch, client.Object, ...client.DeleteOption,
			) error {
				deletes++

				return kerrors.NewNotFound(schema.GroupResource{}, "forbidden")
			},
		}).
		Build()
	r := &Reconciler{client: cli, log: log.Log}

	reqs := r.handleAllowedSyscallsChanged(t.Context(), &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"read"}},
		},
	})
	require.Len(t, reqs, 1)
	require.Equal(t, 1, deletes)
}

// Resolving a profile must not pull its OCI base profile while handling the
// SPOD event. The reconcile of the profile validates it instead.
func TestHandleAllowedSyscallsChangedDoesNotPull(t *testing.T) {
	t.Parallel()

	sp := newTestProfile()
	sp.Spec.BaseProfileName = "oci://registry/base:v1"

	env := newReconcileEnv(t, sp)
	env.rec.baseProfiles = ttlcache.New[string, *seccompprofileapi.SeccompProfile]()

	spod := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"exit"}},
		},
	}

	reqs := env.rec.handleAllowedSyscallsChanged(t.Context(), spod)
	require.Len(t, reqs, 1)
	require.Zero(t, env.impl.PullCallCount())

	require.NoError(
		t,
		env.cli.Get(t.Context(), testProfileKey, &seccompprofileapi.SeccompProfile{}),
	)
}

// The API server is only asked if the cache shows a profile sharing the file
// or if the file on disk would change.
func TestHandleFileConflictAvoidsUncachedReads(t *testing.T) {
	t.Parallel()

	later := newTestProfile()
	later.Name = testProfile + seccompprofileapi.ExtJSON
	later.CreationTimestamp = metav1.Unix(200, 0)

	owner := newTestProfile()
	owner.CreationTimestamp = metav1.Unix(100, 0)

	env := newReconcileEnv(t, later)
	env.rec.profileRoot = t.TempDir()

	apiReads := 0
	env.rec.reader = interceptor.NewClient(
		fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(owner, later).Build(),
		interceptor.Funcs{Get: func(
			ctx context.Context, c client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption,
		) error {
			apiReads++

			return c.Get(ctx, key, obj, opts...)
		}},
	)

	nodeStatus, err := nodestatus.NewForProfileOnNode(later, env.cli, testNode)
	require.NoError(t, err)

	content := []byte("content")
	path := env.rec.profilePath(later)
	require.NoError(t, os.WriteFile(path, content, 0o600))

	// The file stays the same and the cache knows no other profile.
	conflict, err := env.rec.handleFileConflict(
		t.Context(),
		later,
		nodeStatus,
		path,
		content,
		log.Log,
	)
	require.NoError(t, err)
	require.False(t, conflict)
	require.Zero(t, apiReads)

	// A changed file is only written if the API server confirms the owner.
	_, err = nodeStatus.Create(t.Context())
	require.NoError(t, err)

	conflict, err = env.rec.handleFileConflict(
		t.Context(), later, nodeStatus, path, []byte("changed"), log.Log,
	)
	require.NoError(t, err)
	require.True(t, conflict)
	require.Equal(t, 1, apiReads)
}
