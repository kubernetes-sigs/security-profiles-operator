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

package selinuxprofile

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
)

const (
	testReconcileNode      = "node-1"
	testReconcileNamespace = "security-profiles-operator"
	testReconcilePod       = "spod-abc"
	testReconcileImage     = "registry.example.com/selinuxd:test"
	testReconcileProfile   = "my-policy"
)

var errTestValidation = errors.New("invalid permission")

// fakeHandler is a SelinuxObjectHandler that serves the profile from the
// client, so that the reconciler sees the state the test prepared.
type fakeHandler struct {
	sp          *selinuxprofileapi.SelinuxProfile
	validateErr error
}

func (f *fakeHandler) Init(ctx context.Context, cli client.Client, key types.NamespacedName) error {
	return cli.Get(ctx, key, f.sp)
}

func (f *fakeHandler) GetProfileObject() selinuxprofileapi.SelinuxProfileObject {
	return f.sp
}

func (f *fakeHandler) Validate(context.Context) error {
	return f.validateErr
}

func (f *fakeHandler) GetCILPolicy() (string, error) {
	return "(blockinherit container)", nil
}

type reconcileFixture struct {
	r        *ReconcileSelinux
	client   client.Client
	recorder *events.FakeRecorder
	request  reconcile.Request
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, selinuxprofileapi.AddToScheme(scheme))
	require.NoError(t, secprofnodestatusapi.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))

	return scheme
}

func newReconcileFixture(
	t *testing.T,
	profile *selinuxprofileapi.SelinuxProfile,
	validateErr error,
	selinuxd http.HandlerFunc,
) *reconcileFixture {
	t.Helper()

	t.Setenv(config.NodeNameEnvKey, testReconcileNode)
	t.Setenv(config.OperatorNamespaceEnvKey, testReconcileNamespace)
	t.Setenv("POD_NAME", testReconcilePod)

	scheme := testScheme(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testReconcilePod, Namespace: testReconcileNamespace},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name:  bindata.SelinuxContainerName,
			Image: testReconcileImage,
		}}},
	}

	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		WithObjects(pod)
	if profile != nil {
		builder = builder.WithObjects(profile)
	}

	cli := builder.Build()
	recorder := events.NewFakeRecorder(20)

	r := &ReconcileSelinux{
		client:         cli,
		clientReader:   cli,
		scheme:         scheme,
		record:         recorder,
		metrics:        metrics.New(),
		log:            logf.Log.WithName("test"),
		controllerName: "selinuxprofile",
		objectHandlerInit: func(
			ctx context.Context, c client.Client, key types.NamespacedName,
		) (SelinuxObjectHandler, error) {
			oh := &fakeHandler{sp: &selinuxprofileapi.SelinuxProfile{}, validateErr: validateErr}
			err := oh.Init(ctx, c, key)

			return oh, err
		},
		httpc: selinuxdTestClient(t, selinuxd),
	}

	return &reconcileFixture{
		r:        r,
		client:   cli,
		recorder: recorder,
		request: reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: testReconcileNamespace, Name: testReconcileProfile,
		}},
	}
}

func testProfile() *selinuxprofileapi.SelinuxProfile {
	return &selinuxprofileapi.SelinuxProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: selinuxprofileapi.GroupVersion.String(),
			Kind:       "SelinuxProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       testReconcileProfile,
			Namespace:  testReconcileNamespace,
			Generation: 1,
		},
	}
}

// selinuxd returns a handler that answers the ready probe and, for a policy
// lookup, the given status code and body.
func selinuxd(t *testing.T, ready bool, policyCode int, policyBody string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ready") {
			if ready {
				writeBody(t, w, `{"ready": true}`)
			} else {
				writeBody(t, w, `{"ready": false}`)
			}

			return
		}

		w.WriteHeader(policyCode)

		if policyBody != "" {
			writeBody(t, w, policyBody)
		}
	}
}

func (f *reconcileFixture) profile(t *testing.T) *selinuxprofileapi.SelinuxProfile {
	t.Helper()

	sp := &selinuxprofileapi.SelinuxProfile{}
	require.NoError(t, f.client.Get(context.Background(), f.request.NamespacedName, sp))

	return sp
}

func (f *reconcileFixture) nodeStatus(
	t *testing.T,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	t.Helper()

	list := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	require.NoError(t, f.client.List(context.Background(), list))
	require.Len(t, list.Items, 1, "expected exactly one node status")

	return &list.Items[0]
}

func (f *reconcileFixture) events() []string {
	var out []string

	for {
		select {
		case e := <-f.recorder.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// prepareDeletion installs the node status and finalizer as a previous
// reconcile would have, then deletes the profile so that only the finalizer
// keeps it around.
func (f *reconcileFixture) prepareDeletion(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	sp := f.profile(t)
	sp.SetGroupVersionKind(selinuxprofileapi.GroupVersion.WithKind("SelinuxProfile"))

	ns, err := nodestatus.NewForProfile(sp, f.client)
	require.NoError(t, err)

	_, err = ns.Create(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Delete(ctx, f.profile(t)))

	deleted := f.profile(t)
	require.False(t, deleted.GetDeletionTimestamp().IsZero())
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileProfileNotFound(t *testing.T) {
	f := newReconcileFixture(t, nil, nil, selinuxd(t, true, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err, "a deleted profile must not be retried")
	require.Equal(t, reconcile.Result{}, res)
	require.Empty(t, f.events())
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileHandlerInitError(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))
	f.r.objectHandlerInit = func(
		context.Context, client.Client, types.NamespacedName,
	) (SelinuxObjectHandler, error) {
		return nil, kerrors.NewServiceUnavailable("api server down")
	}

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.Error(t, err)
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileSelinuxdNotReady(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, false, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)

	// The first reconcile registers this node on the profile even when
	// selinuxd cannot install anything yet.
	sp := f.profile(t)
	require.Len(t, sp.GetFinalizers(), 1)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, f.nodeStatus(t).Status.Status)
	require.Equal(t, testReconcileNode, f.nodeStatus(t).Spec.NodeName)
	require.Equal(t,
		[]string{"Warning " + reasonCannotContactSelinuxd + " selinuxd not yet ready"},
		f.events())
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileSelinuxdUnreachable(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil,
		func(w http.ResponseWriter, _ *http.Request) {
			writeBody(t, w, "not json")
		})

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.ErrorContains(t, err, "contacting selinuxd")

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonCannotContactSelinuxd+" "))
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileValidationFailure(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), errTestValidation,
		selinuxd(t, true, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err, "an invalid profile must not be retried until it changes")
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)
	require.Equal(t,
		string(secprofnodestatusapi.ProfileStateError),
		f.nodeStatus(t).Labels[secprofnodestatusapi.StatusStateLabel])

	evts := f.events()
	require.Len(t, evts, 1)
	require.Contains(t, evts[0], "Warning "+reasonCannotInstallPolicy)
	require.Contains(t, evts[0], testReconcileNode)
	require.Contains(t, evts[0], errTestValidation.Error())
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileDisabledProfileIsSkipped(t *testing.T) {
	sp := testProfile()
	sp.Spec.State = profilebasev1.SpecStateDisabled

	f := newReconcileFixture(t, sp, nil,
		func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/ready") {
				t.Errorf("a disabled profile must not be looked up in selinuxd: %s", r.URL.Path)
			}

			writeBody(t, w, `{"ready": true}`)
		})

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, f.nodeStatus(t).Status.Status)
	require.Empty(t, f.events())
}

//nolint:paralleltest // uses t.Setenv
func TestReconcilePartialProfileIsSkipped(t *testing.T) {
	sp := testProfile()
	sp.Labels = map[string]string{profilebasev1.ProfilePartialLabel: "true"}

	f := newReconcileFixture(t, sp, nil, selinuxd(t, true, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStatePartial, f.nodeStatus(t).Status.Status)
}

//nolint:paralleltest // uses t.Setenv
func TestReconcilePolicyFileWriteFailure(t *testing.T) {
	if _, err := os.Stat(bindata.SelinuxDropDirectory); err == nil {
		t.Skipf("%s exists on this host, the policy file could be written",
			bindata.SelinuxDropDirectory)
	}

	if isSELinuxModuleInstalled(bindata.SelinuxModuleStorePath, testReconcileProfile) {
		t.Skip("the test profile name collides with a system module on this host")
	}

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.ErrorContains(t, err, "creating policy file")

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonCannotWritePolicyFile+" "))
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileDeletionSelinuxdNotReady(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, false, http.StatusOK, ""))
	f.prepareDeletion(t)

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, f.nodeStatus(t).Status.Status)
	require.Len(t, f.profile(t).GetFinalizers(), 1,
		"the finalizer must stay until the policy is gone")
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileDeletionPolicyStillInstalled(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	f.prepareDeletion(t)

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.Len(t, f.profile(t).GetFinalizers(), 1)
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, f.nodeStatus(t).Status.Status)
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileDeletionSelinuxdError(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusInternalServerError, ""))
	f.prepareDeletion(t)

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.ErrorContains(t, err, "looking up policy status")
	require.Len(t, f.profile(t).GetFinalizers(), 1)

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonCannotRemovePolicy+" "))
}

//nolint:paralleltest // uses t.Setenv
func TestReconcileDeletionPolicyRemoved(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusNotFound, ""))
	f.prepareDeletion(t)

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	ctx := context.Background()

	// With the last finalizer gone the profile and its node status are gone.
	err = f.client.Get(ctx, f.request.NamespacedName, &selinuxprofileapi.SelinuxProfile{})
	require.True(t, kerrors.IsNotFound(err), "profile should be deleted, got %v", err)

	statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	require.NoError(t, f.client.List(ctx, statuses))
	require.Empty(t, statuses.Items)

	// The kernel keeps the removed module loaded until the policy is
	// reloaded, so the removal has to schedule a reload on this node.
	jobs := &batchv1.JobList{}
	require.NoError(t, f.client.List(ctx, jobs, client.InNamespace(testReconcileNamespace)))
	require.Len(t, jobs.Items, 1)
	require.Equal(t, "remove", jobs.Items[0].Labels["action"])
	require.Equal(t, testReconcileProfile, jobs.Items[0].Labels["policy"])
	require.Equal(t, testReconcileNode, jobs.Items[0].Spec.Template.Spec.NodeName)
	require.Empty(t, f.events())
}

func TestReconcileDeletionReloadJobFailure(t *testing.T) {
	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusNotFound, ""))
	f.prepareDeletion(t)

	// Without the own pod the reload job cannot find the selinuxd image.
	t.Setenv("POD_NAME", "missing-pod")

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err, "a failed reload must not block the deletion")

	err = f.client.Get(
		context.Background(), f.request.NamespacedName, &selinuxprofileapi.SelinuxProfile{},
	)
	require.True(t, kerrors.IsNotFound(err), "profile should be deleted, got %v", err)

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonCannotReloadPolicy+" "))
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		body    string
		wantErr string
	}{
		"ready":     {body: `{"ready": true}`},
		"not ready": {body: `{"ready": false}`, wantErr: "not ready"},
		"malformed": {body: "not json", wantErr: "getting health status"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := &ReconcileSelinux{
				httpc: selinuxdTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
					writeBody(t, w, tc.body)
				}),
			}

			req, err := http.NewRequestWithContext(
				context.Background(), http.MethodGet, "/healthz", http.NoBody,
			)
			require.NoError(t, err)

			err = r.Healthz(req)
			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
