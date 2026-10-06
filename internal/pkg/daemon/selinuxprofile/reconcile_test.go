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
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
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

func newReconcileFixture(
	t *testing.T,
	profile *selinuxprofileapi.SelinuxProfile,
	validateErr error,
	selinuxd http.HandlerFunc,
) *reconcileFixture {
	t.Helper()

	scheme := utiltest.NewScheme(t)
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
		client:          cli,
		clientReader:    cli,
		scheme:          scheme,
		record:          recorder,
		metrics:         metrics.New(),
		log:             logf.Log.WithName("test"),
		controllerName:  "selinuxprofile",
		nodeName:        testReconcileNode,
		namespace:       testReconcileNamespace,
		podName:         testReconcilePod,
		policyDir:       t.TempDir(),
		moduleStorePath: t.TempDir(),
		objectHandlerInit: func(
			ctx context.Context, c client.Client, key types.NamespacedName, _ string,
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
// keeps it around. The node status is already terminating, like after the
// first deletion pass.
func (f *reconcileFixture) prepareDeletion(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	sp := f.profile(t)
	sp.SetGroupVersionKind(selinuxprofileapi.GroupVersion.WithKind("SelinuxProfile"))

	ns, err := nodestatus.NewForProfileOnNode(sp, f.client, testReconcileNode)
	require.NoError(t, err)

	_, err = ns.Create(ctx)
	require.NoError(t, err)
	require.NoError(t, ns.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateTerminating))
	require.NoError(t, f.client.Delete(ctx, f.profile(t)))

	deleted := f.profile(t)
	require.False(t, deleted.GetDeletionTimestamp().IsZero())
}

func TestReconcileDeletionMarksStatusTerminating(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusNotFound, ""))
	ctx := context.Background()

	ns, err := nodestatus.NewForProfileOnNode(f.profile(t), f.client, testReconcileNode)
	require.NoError(t, err)
	_, err = ns.Create(ctx)
	require.NoError(t, err)
	require.NoError(t, f.client.Delete(ctx, f.profile(t)))

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, f.nodeStatus(t).Status.Status)
	require.Len(t, f.profile(t).GetFinalizers(), 1)
}

// A foreground deletion removes the owned node statuses before the profile.
// The policy must still be removed and the finalizer of the node dropped,
// otherwise the profile is stuck in deletion forever.
func TestReconcileDeletionWithoutNodeStatus(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusNotFound, ""))
	f.prepareDeletion(t)

	ctx := context.Background()
	require.NoError(t, f.client.Delete(ctx, f.nodeStatus(t)))

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	err = f.client.Get(ctx, f.request.NamespacedName, &selinuxprofileapi.SelinuxProfile{})
	require.True(t, kerrors.IsNotFound(err), "profile should be deleted, got %v", err)
}

func TestReconcileProfileNotFound(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, nil, nil, selinuxd(t, true, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err, "a deleted profile must not be retried")
	require.Equal(t, reconcile.Result{}, res)
	require.Empty(t, f.events())
}

func TestReconcileHandlerInitError(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))
	f.r.objectHandlerInit = func(
		context.Context, client.Client, types.NamespacedName, string,
	) (SelinuxObjectHandler, error) {
		return nil, kerrors.NewServiceUnavailable("api server down")
	}

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.Error(t, err)
}

func TestReconcileSelinuxdNotReady(t *testing.T) {
	t.Parallel()

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

func TestReconcileSelinuxdUnreachable(t *testing.T) {
	t.Parallel()

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

func TestReconcileValidationFailure(t *testing.T) {
	t.Parallel()

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

func TestReconcileMissingInheritIsRetried(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), ErrInheritNotFound,
		selinuxd(t, true, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: inheritRetryInterval}, res,
		"the inherited profile may still be created")
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)
}

func TestReconcileTemporaryValidationFailure(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), errTemporaryValidation,
		selinuxd(t, true, http.StatusOK, ""))

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.ErrorIs(t, err, errTemporaryValidation)
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, f.nodeStatus(t).Status.Status,
		"an API server failure is not a problem of the profile")
	require.Empty(t, f.events())
}

// inheritingFakeHandler is a fakeHandler whose policy inherits from other
// profiles of the operator.
type inheritingFakeHandler struct {
	fakeHandler

	ancestors []selinuxprofileapi.SelinuxProfileObject
}

func (f *inheritingFakeHandler) inheritedProfiles() []selinuxprofileapi.SelinuxProfileObject {
	return f.ancestors
}

func TestReconcileWaitsForInheritedProfile(t *testing.T) {
	t.Parallel()

	ancestor := testProfile()
	ancestor.Name = "ancestor"

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))
	require.NoError(t, f.client.Create(context.Background(), ancestor))

	f.r.objectHandlerInit = func(
		ctx context.Context, c client.Client, key types.NamespacedName, _ string,
	) (SelinuxObjectHandler, error) {
		oh := &inheritingFakeHandler{
			fakeHandler: fakeHandler{sp: &selinuxprofileapi.SelinuxProfile{}},
			ancestors:   []selinuxprofileapi.SelinuxProfileObject{ancestor},
		}

		err := oh.Init(ctx, c, key)

		return oh, err
	}

	// The ancestor has no node status on this node yet.
	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.Wait}, res)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	require.NoError(t, f.client.Get(context.Background(), types.NamespacedName{
		Namespace: testReconcileNamespace,
		Name:      "selinuxprofile-" + testReconcileProfile + "-" + testReconcileNode,
	}, status))
	require.Equal(t, secprofnodestatusapi.ProfileStatePending, status.Status.Status)

	// Once the ancestor is installed on the node, the installation proceeds.
	ns, err := nodestatus.NewForProfileOnNode(ancestor, f.client, testReconcileNode)
	require.NoError(t, err)
	_, err = ns.Create(context.Background())
	require.NoError(t, err)
	require.NoError(
		t,
		ns.SetNodeStatus(context.Background(), secprofnodestatusapi.ProfileStateInstalled),
	)

	installed, err := f.r.inheritedProfilesInstalled(
		context.Background(), &inheritingFakeHandler{
			ancestors: []selinuxprofileapi.SelinuxProfileObject{ancestor},
		}, logr.Discard(),
	)
	require.NoError(t, err)
	require.True(t, installed)
}

func TestReconcileDisabledProfileIsSkipped(t *testing.T) {
	t.Parallel()

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

func TestReconcilePartialProfileIsSkipped(t *testing.T) {
	t.Parallel()

	sp := testProfile()
	sp.Labels = map[string]string{profilebasev1.ProfilePartialLabel: "true"}

	f := newReconcileFixture(t, sp, nil, selinuxd(t, true, http.StatusOK, ""))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStatePartial, f.nodeStatus(t).Status.Status)
}

func TestReconcilePolicyFileWriteFailure(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))
	f.r.policyDir = filepath.Join(t.TempDir(), "missing")

	_, err := f.r.Reconcile(context.Background(), f.request)
	require.ErrorContains(t, err, "creating policy file")

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonCannotWritePolicyFile+" "))
}

func (f *reconcileFixture) reloadJobs(t *testing.T) []batchv1.Job {
	t.Helper()

	jobs := &batchv1.JobList{}
	require.NoError(t, f.client.List(context.Background(), jobs,
		client.InNamespace(testReconcileNamespace)))

	return jobs.Items
}

// finishReloadJobs marks the reload jobs as completed, or as failed with a
// true condition.
func (f *reconcileFixture) finishReloadJobs(t *testing.T, condition batchv1.JobConditionType) {
	t.Helper()

	jobs := f.reloadJobs(t)
	for i := range jobs {
		job := &jobs[i]
		if condition == batchv1.JobComplete {
			job.Status.Succeeded = 1
		}

		withCondition(job, condition)
		require.NoError(t, f.client.Status().Update(context.Background(), job))
	}
}

func TestReconcileInstallsPolicy(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	// The first pass writes the policy and gives selinuxd time to install it.
	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.Equal(t, secprofnodestatusapi.ProfileStateInProgress, f.nodeStatus(t).Status.Status)

	content, err := os.ReadFile(filepath.Join(f.r.policyDir, testReconcileProfile+".cil"))
	require.NoError(t, err)
	require.Equal(t, "(blockinherit container)", string(content))

	// Then the installation is reported and the kernel policy reloaded.
	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)
	require.Len(t, f.reloadJobs(t), 1)
	require.Equal(t, "install", f.reloadJobs(t)[0].Labels["action"])
	require.Contains(t, f.events(), "Normal "+reasonInstalledPolicy+
		" Successfully saved profile to disk on "+testReconcileNode)

	// The reload is recorded once the job completed.
	require.Empty(t, f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Empty(t, f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])

	f.finishReloadJobs(t, batchv1.JobComplete)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, "1", f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Empty(t, f.events())

	// The reload is done once per generation.
	_, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Len(t, f.reloadJobs(t), 1)
}

// A reload job which failed for good is replaced by a new one, instead of
// leaving the policy of the generation unloaded. The retries back off and
// only the first failure of the generation is reported.
func TestReconcileRetriesFailedReloadJob(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	for range 2 {
		_, err := f.r.Reconcile(ctx, f.request)
		require.NoError(t, err)
	}

	require.Len(t, f.reloadJobs(t), 1)
	f.events()

	f.finishReloadJobs(t, batchv1.JobFailed)

	// The failed job is deleted and reported.
	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Empty(t, f.reloadJobs(t))
	require.Empty(t, f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Equal(t, []string{
		"Warning " + reasonCannotReloadPolicy + " Policy reload job failed on " +
			testReconcileNode + ", retrying",
	}, f.events())

	// A resync before the retry is due does not create a job.
	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Positive(t, res.RequeueAfter)
	require.LessOrEqual(t, res.RequeueAfter, reloadJobRetryInterval)
	require.Empty(t, f.reloadJobs(t))
	require.Empty(t, f.events())

	// The retry creates a new job. Its failure doubles the delay and is not
	// reported again.
	f.expireReloadBackoff(t)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Len(t, f.reloadJobs(t), 1)

	f.finishReloadJobs(t, batchv1.JobFailed)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: 2 * reloadJobRetryInterval}, res)
	require.Empty(t, f.reloadJobs(t))
	require.Empty(t, f.events())

	// The next job completes, which is recorded.
	f.expireReloadBackoff(t)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Len(t, f.reloadJobs(t), 1)

	f.finishReloadJobs(t, batchv1.JobComplete)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, "1", f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Empty(t, f.events())
	require.Empty(t, f.r.reloadFailures)
}

// expireReloadBackoff lets the retry of the failed reload of the profile
// happen now.
func (f *reconcileFixture) expireReloadBackoff(t *testing.T) {
	t.Helper()

	f.r.reloadFailuresMu.Lock()
	defer f.r.reloadFailuresMu.Unlock()

	failures, ok := f.r.reloadFailures[f.request.NamespacedName]
	require.True(t, ok)

	failures.retryAt = time.Time{}
	f.r.reloadFailures[f.request.NamespacedName] = failures
}

func TestReloadRetryInterval(t *testing.T) {
	t.Parallel()

	for failures, want := range map[int]time.Duration{
		1:   reloadJobRetryInterval,
		2:   2 * reloadJobRetryInterval,
		6:   32 * reloadJobRetryInterval,
		7:   reloadJobMaxRetryInterval,
		100: reloadJobMaxRetryInterval,
	} {
		require.Equal(t, want, reloadRetryInterval(failures), failures)
	}
}

// A failure to read the node status must not report the installation again.
func TestReconcileInstalledNodeStatusReadError(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	f.events()

	// The node status cannot be read once selinuxd reported the policy as
	// installed.
	var policyLookedUp atomic.Bool

	installed := selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`)
	f.setSelinuxd(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/policies/") {
			policyLookedUp.Store(true)
		}

		installed(w, r)
	})

	errGet := errors.New("get failed")
	base, ok := f.client.(client.WithWatch)
	require.True(t, ok)

	f.r.client = interceptor.NewClient(base, interceptor.Funcs{
		Get: func(
			ctx context.Context, c client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption,
		) error {
			if _, isStatus := obj.(*secprofnodestatusapi.SecurityProfileNodeStatus); isStatus &&
				policyLookedUp.Load() {
				return errGet
			}

			return c.Get(ctx, key, obj, opts...)
		},
	})

	_, err = f.r.Reconcile(ctx, f.request)
	require.ErrorIs(t, err, errGet)
	require.Empty(t, f.events())
	require.Empty(t, f.reloadJobs(t))
	require.Equal(t, secprofnodestatusapi.ProfileStateInProgress, f.nodeStatus(t).Status.Status)
}

func TestReconcileInstallationFailed(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Failed", "msg": "semodule failed"}`))
	ctx := context.Background()

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)
	require.Empty(t, f.reloadJobs(t))
	require.Contains(t, f.events(), "Warning "+reasonCannotInstallPolicy+
		" Failed to save profile to disk on "+testReconcileNode+": semodule failed")
}

func TestReconcilePolicyNotInstalledYet(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusNotFound, ""))
	ctx := context.Background()

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.Equal(t, secprofnodestatusapi.ProfileStateInProgress, f.nodeStatus(t).Status.Status)
}

func TestReconcileSystemModuleConflict(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))
	require.NoError(t, os.MkdirAll(filepath.Join(
		f.r.moduleStorePath, "targeted", "active", "modules", "100", testReconcileProfile,
	), 0o755))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonSystemModuleConflict+" "))

	_, err = os.Stat(filepath.Join(f.r.policyDir, testReconcileProfile+".cil"))
	require.True(t, os.IsNotExist(err), "the system module must not be replaced")
}

func TestReconcileDeletionSelinuxdNotReady(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, false, http.StatusOK, ""))
	f.prepareDeletion(t)

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, f.nodeStatus(t).Status.Status)
	require.Len(t, f.profile(t).GetFinalizers(), 1,
		"the finalizer must stay until the policy is gone")
}

func TestReconcileDeletionPolicyStillInstalled(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	f.prepareDeletion(t)

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.Len(t, f.profile(t).GetFinalizers(), 1)
	require.Equal(t, secprofnodestatusapi.ProfileStateTerminating, f.nodeStatus(t).Status.Status)
}

func TestReconcileDeletionSelinuxdError(t *testing.T) {
	t.Parallel()

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

func TestReconcileDeletionPolicyRemoved(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusNotFound, ""))
	f.prepareDeletion(t)

	// Without the own pod the reload job cannot find the selinuxd image.
	f.r.podName = "missing-pod"

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

// runningReloadJob returns an unfinished reload job of the test policy.
func runningReloadJob(action string) *batchv1.Job {
	return createTestJob(
		testReconcileNamespace, "running-"+action,
		testReconcileNode, testReconcileProfile, action, 0, 0,
	)
}

// A reload which has to wait for a running job is retried, because nothing
// else triggers a reconcile of the installed profile.
func TestReconcileRetriesReloadAfterRunningJob(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	running := runningReloadJob("install")
	require.NoError(t, f.client.Create(ctx, running))

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)
	require.Empty(t, f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Len(t, f.reloadJobs(t), 1)
	require.Len(t, f.events(), 1)

	// Once the running job finished, the reload happens, without reporting
	// the installation again.
	running.Status.Succeeded = 1
	require.NoError(t, f.client.Status().Update(ctx, running))

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Len(t, f.reloadJobs(t), 2)

	f.finishReloadJobs(t, batchv1.JobComplete)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, "1", f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Len(t, f.reloadJobs(t), 2)
	require.Empty(t, f.events())

	// A new generation is reloaded again, although the last job is recent.
	sp := f.profile(t)
	sp.Generation = 2
	require.NoError(t, f.client.Update(ctx, sp))

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Len(t, f.reloadJobs(t), 3)

	f.finishReloadJobs(t, batchv1.JobComplete)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, "2", f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Len(t, f.reloadJobs(t), 3)
}

func TestReconcileRetriesFailedReloadJobCreation(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)

	// Without the own pod the reload job cannot find the selinuxd image.
	f.r.podName = "missing-pod"

	_, err = f.r.Reconcile(ctx, f.request)
	require.ErrorContains(t, err, "creating policy reload job")
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)
	require.Empty(t, f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
	require.Contains(t, strings.Join(f.events(), "\n"), "Warning "+reasonCannotReloadPolicy)
}

func TestReconcileDeletionWaitsForRunningReloadJob(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusNotFound, ""))
	f.prepareDeletion(t)

	require.NoError(t, f.client.Create(context.Background(), runningReloadJob("remove")))

	res, err := f.r.Reconcile(context.Background(), f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: reloadJobRetryInterval}, res)
	require.Len(t, f.profile(t).GetFinalizers(), 1,
		"the finalizer must stay until the removal got reloaded")
}

// setSelinuxd replaces the selinuxd the reconciler talks to.
func (f *reconcileFixture) setSelinuxd(t *testing.T, handler http.HandlerFunc) {
	t.Helper()

	f.r.httpc = selinuxdTestClient(t, handler)
}

// A policy which got installed and is disabled afterwards has to be removed
// from the node, but only once the pods using it are gone.
func TestReconcileEnabledToDisabled(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	for range 2 {
		_, err := f.r.Reconcile(ctx, f.request)
		require.NoError(t, err)
	}

	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)

	policyFile := filepath.Join(f.r.policyDir, testReconcileProfile+".cil")
	require.FileExists(t, policyFile)

	sp := f.profile(t)
	sp.Spec.State = profilebasev1.SpecStateDisabled
	sp.Generation = 2
	sp.SetFinalizers(append(sp.GetFinalizers(), util.HasActivePodsFinalizerString))
	require.NoError(t, f.client.Update(ctx, sp))

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: common.InUseRetry}, res)
	require.FileExists(t, policyFile)

	sp = f.profile(t)
	sp.SetFinalizers([]string{util.GetFinalizerNodeString(testReconcileNode)})
	require.NoError(t, f.client.Update(ctx, sp))

	// The policy file goes first, then selinuxd removes the module.
	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.NoFileExists(t, policyFile)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)

	f.setSelinuxd(t, selinuxd(t, true, http.StatusNotFound, ""))

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateDisabled, f.nodeStatus(t).Status.Status)
	require.Equal(t, "2", f.nodeStatus(t).Annotations[reloadRemoveGenerationAnnotation])

	var removeJobs int

	for _, job := range f.reloadJobs(t) {
		if job.Labels["action"] == "remove" {
			removeJobs++
		}
	}

	require.Equal(t, 1, removeJobs)

	// Nothing is left to do for the disabled profile.
	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Len(t, f.reloadJobs(t), 2)
}

// testRawProfile returns a RawSelinuxProfile with the name of the test
// profile, which gives it the same policy name.
func testRawProfile(created int64) *selinuxprofileapi.RawSelinuxProfile {
	return &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:              testReconcileProfile,
			Namespace:         testReconcileNamespace,
			CreationTimestamp: metav1.Unix(created, 0),
		},
	}
}

// A SelinuxProfile and a RawSelinuxProfile of the same name share the policy
// file and module. The later one must not replace the policy of the other.
func TestReconcilePolicyNameConflict(t *testing.T) {
	t.Parallel()

	sp := testProfile()
	sp.CreationTimestamp = metav1.Unix(200, 0)

	f := newReconcileFixture(t, sp, nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	raw := testRawProfile(100)
	require.NoError(t, f.client.Create(ctx, raw))

	policyFile := filepath.Join(f.r.policyDir, testReconcileProfile+".cil")
	require.NoError(t, os.WriteFile(policyFile, []byte("raw policy"), 0o600))

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)

	evts := f.events()
	require.Len(t, evts, 1)
	require.True(t, strings.HasPrefix(evts[0], "Warning "+reasonPolicyNameConflict+" "), evts[0])
	require.Contains(t, evts[0], "RawSelinuxProfile "+testReconcileProfile)

	content, err := os.ReadFile(policyFile)
	require.NoError(t, err)
	require.Equal(t, "raw policy", string(content), "the policy of the owner must stay")

	// Deleting the later profile keeps the policy of the owner as well.
	f.prepareDeletion(t)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.FileExists(t, policyFile)
	require.Empty(t, f.reloadJobs(t))

	err = f.client.Get(ctx, f.request.NamespacedName, &selinuxprofileapi.SelinuxProfile{})
	require.True(t, kerrors.IsNotFound(err), "profile should be deleted, got %v", err)
}

func TestReconcilePolicyNameConflictResolved(t *testing.T) {
	t.Parallel()

	sp := testProfile()
	sp.CreationTimestamp = metav1.Unix(200, 0)

	f := newReconcileFixture(t, sp, nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	raw := testRawProfile(100)
	require.NoError(t, f.client.Create(ctx, raw))

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)

	// Once the owner is gone, the watch enqueues the profile, which then
	// installs its policy.
	require.NoError(t, f.client.Delete(ctx, raw))

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.FileExists(t, filepath.Join(f.r.policyDir, testReconcileProfile+".cil"))
}

func TestOwnsPolicyBefore(t *testing.T) {
	t.Parallel()

	older := testProfile()
	older.CreationTimestamp = metav1.Unix(100, 0)

	newer := testRawProfile(200)
	require.True(t, ownsPolicyBefore(older, newer))
	require.False(t, ownsPolicyBefore(newer, older))

	// On a tie the SelinuxProfile wins, whichever is asked.
	sameTime := testRawProfile(100)
	require.True(t, ownsPolicyBefore(older, sameTime))
	require.False(t, ownsPolicyBefore(sameTime, older))
}

func TestSelinuxOptionsChangedPredicate(t *testing.T) {
	t.Parallel()

	old := &spodapi.SecurityProfilesOperatorDaemon{}
	changed := old.DeepCopy()
	changed.Spec.Selinux.Options.AllowedSystemProfiles = []string{"container"}

	unrelated := old.DeepCopy()
	unrelated.Spec.Security.AllowedSyscalls = []string{"read"}

	require.True(t, selinuxOptionsChangedPredicate.Update(
		event.UpdateEvent{ObjectOld: old, ObjectNew: changed}))
	require.False(t, selinuxOptionsChangedPredicate.Update(
		event.UpdateEvent{ObjectOld: old, ObjectNew: unrelated}))
	require.False(t, selinuxOptionsChangedPredicate.Create(event.CreateEvent{Object: old}))
}

func TestSelinuxProfileRequests(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil, selinuxd(t, true, http.StatusOK, ""))

	reqs := f.r.selinuxProfileRequests(
		context.Background(), &spodapi.SecurityProfilesOperatorDaemon{},
	)
	require.Equal(t, []reconcile.Request{f.request}, reqs)
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

// A reload which cannot be recorded is retried, and the retry must not create
// another job: the job carries the generation it reloads.
func TestReconcileRetriesUnrecordedReload(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	for range 2 {
		_, err := f.r.Reconcile(ctx, f.request)
		require.NoError(t, err)
	}

	require.Len(t, f.reloadJobs(t), 1)
	f.finishReloadJobs(t, batchv1.JobComplete)

	errUpdate := errors.New("update failed")
	base, ok := f.client.(client.WithWatch)
	require.True(t, ok)

	f.r.client = interceptor.NewClient(base, interceptor.Funcs{
		Update: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			if _, recorded := obj.GetAnnotations()[reloadInstallGenerationAnnotation]; recorded {
				return errUpdate
			}

			return c.Update(ctx, obj, opts...)
		},
	})

	_, err := f.r.Reconcile(ctx, f.request)
	require.ErrorIs(t, err, errUpdate)
	require.Len(t, f.reloadJobs(t), 1)
	require.Equal(t, "1", f.reloadJobs(t)[0].Labels[reloadJobLabelGeneration])
	require.Empty(t, f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])

	f.r.client = f.client

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Len(t, f.reloadJobs(t), 1, "the job of the generation must be reused")
	require.Equal(t, "1", f.nodeStatus(t).Annotations[reloadInstallGenerationAnnotation])
}

// The periodic resyncs of the daemon cache reconcile an installed policy
// again. That must neither rewrite the policy file nor reload the policy, but
// a policy file which got removed from the node is written again.
func TestReconcileResyncOfInstalledPolicy(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), nil,
		selinuxd(t, true, http.StatusOK, `{"status": "Installed", "msg": ""}`))
	ctx := context.Background()

	for range 2 {
		_, err := f.r.Reconcile(ctx, f.request)
		require.NoError(t, err)
	}

	f.finishReloadJobs(t, batchv1.JobComplete)

	res, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	f.events()

	policyFile := filepath.Join(f.r.policyDir, testReconcileProfile+".cil")
	written, err := os.Stat(policyFile)
	require.NoError(t, err)

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Empty(t, f.events())
	require.Len(t, f.reloadJobs(t), 1)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, f.nodeStatus(t).Status.Status)

	resynced, err := os.Stat(policyFile)
	require.NoError(t, err)
	require.True(t, os.SameFile(written, resynced), "the policy file must not be rewritten")

	require.NoError(t, os.Remove(policyFile))

	res, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Equal(t, selinuxdPollInterval, res.RequeueAfter)
	require.FileExists(t, policyFile)
	require.Len(t, f.reloadJobs(t), 1)
}

// A profile which cannot be installed is reconciled again by every resync of
// the daemon cache, which must not report the same error again.
func TestReconcileReportsInstallErrorOnce(t *testing.T) {
	t.Parallel()

	f := newReconcileFixture(t, testProfile(), errTestValidation,
		selinuxd(t, true, http.StatusOK, ""))
	ctx := context.Background()

	for range 3 {
		_, err := f.r.Reconcile(ctx, f.request)
		require.NoError(t, err)
	}

	require.Len(t, f.events(), 1)
	require.Equal(t, secprofnodestatusapi.ProfileStateError, f.nodeStatus(t).Status.Status)

	// A new generation of the profile is reported again.
	sp := f.profile(t)
	sp.Generation = 2
	require.NoError(t, f.client.Update(ctx, sp))

	_, err := f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)

	evts := f.events()
	require.Len(t, evts, 1)
	require.Contains(t, evts[0], "Warning "+reasonCannotInstallPolicy)

	// Once the profile is gone, the reported error is forgotten.
	sp = f.profile(t)
	sp.Finalizers = nil
	require.NoError(t, f.client.Update(ctx, sp))
	require.NoError(t, f.client.Delete(ctx, sp))

	_, err = f.r.Reconcile(ctx, f.request)
	require.NoError(t, err)
	require.Empty(t, f.r.reported)
}
