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

package spod

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const testNamespace = "security-profiles-operator"

var errTest = errors.New("test")

func reconcileTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, spodapi.AddToScheme(scheme))
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))
	require.NoError(t, certmanagerv1.AddToScheme(scheme))
	require.NoError(t, monitoringv1.AddToScheme(scheme))

	return scheme
}

// newReconcileTest returns a reconciler with a fake client which holds the
// operator deployment and the provided SPOD.
func newReconcileTest(
	t *testing.T,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	funcs *interceptor.Funcs,
	objs ...client.Object,
) (*ReconcileSPOd, client.Client, *events.FakeRecorder) {
	t.Helper()

	scheme := reconcileTestScheme(t)
	operator := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: config.OperatorName, Namespace: testNamespace},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "operator", Image: "operator-image"}},
		}}},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(append(objs, spod, operator)...).
		WithStatusSubresource(spod).
		WithInterceptorFuncs(*funcs).
		Build()

	recorder := events.NewFakeRecorder(100)

	return &ReconcileSPOd{
		client:       cl,
		clientReader: cl,
		scheme:       scheme,
		baseSPOd:     bindata.Manifest.DeepCopy(),
		record:       recorder,
		log:          logf.Log,
		namespace:    testNamespace,
		// The fake client serves the cert-manager API.
		watchesCertManager: true,
	}, cl, recorder
}

func testSPOD() *spodapi.SecurityProfilesOperatorDaemon {
	spod := bindata.DefaultSPOD.DeepCopy()
	spod.Namespace = testNamespace

	return spod
}

func reconcileSPOD(t *testing.T, r *ReconcileSPOd) {
	t.Helper()

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: config.SPOdName, Namespace: testNamespace},
	})
	require.NoError(t, err)
}

func spodState(t *testing.T, cl client.Client) spodapi.SPODState {
	t.Helper()

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, spod))

	return spod.Status.State
}

func TestReconcileLifecycle(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Spec.Enricher.EnableLogEnricher = new(true)

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})

	// The initial status.
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStatePending, spodState(t, cl))

	// All operands get created.
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateCreating, spodState(t, cl))

	ds := &appsv1.DaemonSet{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, ds))
	require.Equal(t, "operator-image", ds.Spec.Template.Spec.Containers[0].Image)

	for _, obj := range []client.Object{
		&admissionregv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{
			Name: "spo-mutating-webhook-configuration",
		}},
		&admissionregv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{
			Name: "spo-validating-webhook-configuration",
		}},
		&admissionregv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{
			Name: bindata.RecordingProfilesPolicyName,
		}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
			Name: config.OperatorName + "-webhook", Namespace: testNamespace,
		}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "metrics", Namespace: testNamespace}},
		&certmanagerv1.Issuer{ObjectMeta: metav1.ObjectMeta{
			Name: "selfsigned-issuer", Namespace: testNamespace,
		}},
		&monitoringv1.ServiceMonitor{ObjectMeta: metav1.ObjectMeta{
			Name: "security-profiles-operator-monitor", Namespace: testNamespace,
		}},
		&seccompprofileapi.SeccompProfile{ObjectMeta: metav1.ObjectMeta{
			Name: config.LogEnricherProfile,
		}},
	} {
		require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(obj), obj), "%T", obj)
	}

	// Nothing changed, so the SPOD is running.
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateRunning, spodState(t, cl))

	// A configuration change updates the operands.
	spod = &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, spod))
	spod.Spec.Verbosity = 1
	require.NoError(t, cl.Update(t.Context(), spod))

	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateUpdating, spodState(t, cl))
}

func TestReconcileRemovesLegacyAppArmorAnnotation(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})
	reconcileSPOD(t, r)

	key := types.NamespacedName{Name: config.SPOdName, Namespace: testNamespace}
	ds := &appsv1.DaemonSet{}
	require.NoError(t, cl.Get(t.Context(), key, ds))

	ds.Annotations = map[string]string{legacyAppArmorAnnotation: "unconfined"}
	require.NoError(t, cl.Update(t.Context(), ds))

	reconcileSPOD(t, r)
	require.NoError(t, cl.Get(t.Context(), key, ds))
	require.NotContains(t, ds.Annotations, legacyAppArmorAnnotation)
}

// The admission policies only harden the cluster, so failing to apply them
// must not block the operands. They are applied again on the next
// reconciliation.
func TestReconcileAdmissionPolicyFailure(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	fail := true
	r, cl, recorder := newReconcileTest(t, spod, &interceptor.Funcs{
		Create: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption,
		) error {
			if _, ok := obj.(*admissionregv1.ValidatingAdmissionPolicy); ok && fail {
				return errTest
			}

			return c.Create(ctx, obj, opts...)
		},
	})

	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateCreating, spodState(t, cl))
	require.Contains(t, <-recorder.Events, reasonCannotApplyAdmissionPolicies)

	fail = false

	reconcileSPOD(t, r)

	key := client.ObjectKey{Name: bindata.RecordingProfilesPolicyName}
	policy := &admissionregv1.ValidatingAdmissionPolicy{}
	require.NoError(t, cl.Get(t.Context(), key, policy))

	// A deleted policy gets restored.
	require.NoError(t, cl.Delete(t.Context(), policy))
	reconcileSPOD(t, r)
	require.NoError(t, cl.Get(t.Context(), key, policy))
}

func TestReconcileSkipsUnservedAdmissionPolicies(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	var policyCalls atomic.Int32

	countPolicy := func(obj client.Object) {
		switch obj.(type) {
		case *admissionregv1.ValidatingAdmissionPolicy,
			*admissionregv1.ValidatingAdmissionPolicyBinding:
			policyCalls.Add(1)
		}
	}

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{
		Get: func(
			ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
		) error {
			countPolicy(obj)

			return c.Get(ctx, key, obj, opts...)
		},
		Create: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption,
		) error {
			countPolicy(obj)

			return c.Create(ctx, obj, opts...)
		},
	})
	r.skipAdmissionPolicies = true

	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateCreating, spodState(t, cl))
	require.Zero(t, policyCalls.Load())
}

func TestReconcileWithoutOperatorDeployment(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	scheme := reconcileTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(spod).Build()
	r := &ReconcileSPOd{client: cl, log: logf.Log, namespace: testNamespace}

	reconcileSPOD(t, r)

	require.True(t, apierrors.IsNotFound(cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, &appsv1.DaemonSet{})))
	require.Equal(t, spodapi.SPODStatePending, spodState(t, cl))
}

func TestReconcileMissingSPOD(t *testing.T) {
	t.Parallel()

	cl := fake.NewClientBuilder().WithScheme(reconcileTestScheme(t)).Build()
	r := &ReconcileSPOd{client: cl, log: logf.Log, namespace: testNamespace}

	reconcileSPOD(t, r)

	// Nothing gets created for a SPOD which does not exist.
	require.True(t, apierrors.IsNotFound(cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, &appsv1.DaemonSet{})))

	svcs := &corev1.ServiceList{}
	require.NoError(t, cl.List(t.Context(), svcs))
	require.Empty(t, svcs.Items)
}

func TestServesAdmissionPolicies(t *testing.T) {
	t.Parallel()

	mapper := meta.NewDefaultRESTMapper(nil)
	serves, err := ServesAdmissionPolicies(mapper)
	require.NoError(t, err)
	require.False(t, serves)

	mapper.Add(
		admissionregv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicy"),
		meta.RESTScopeRoot,
	)

	serves, err = ServesAdmissionPolicies(mapper)
	require.NoError(t, err)
	require.False(t, serves, "the binding kind is missing")

	mapper.Add(
		admissionregv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicyBinding"),
		meta.RESTScopeRoot,
	)

	serves, err = ServesAdmissionPolicies(mapper)
	require.NoError(t, err)
	require.True(t, serves)

	// A failed discovery is not mistaken for a missing API.
	_, err = ServesAdmissionPolicies(failingRESTMapper{mapper})
	require.ErrorIs(t, err, errTest)
}

// failingRESTMapper is a REST mapper whose discovery fails.
type failingRESTMapper struct {
	meta.RESTMapper
}

func (failingRESTMapper) RESTMapping(schema.GroupKind, ...string) (*meta.RESTMapping, error) {
	return nil, errTest
}

// setDaemonSetStatus sets the status of the SPOd DaemonSet.
func setDaemonSetStatus(t *testing.T, cl client.Client, status appsv1.DaemonSetStatus) {
	t.Helper()

	ds := &appsv1.DaemonSet{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, ds))

	status.ObservedGeneration = ds.Generation
	ds.Status = status
	require.NoError(t, cl.Status().Update(t.Context(), ds))
}

// The SPOD is only running once every pod is updated and available, and
// leaves that state once pods become unavailable.
func TestReconcileRunningFollowsRollout(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateCreating, spodState(t, cl))

	rolledOut := appsv1.DaemonSetStatus{
		DesiredNumberScheduled: 2,
		UpdatedNumberScheduled: 2,
		NumberAvailable:        2,
		NumberReady:            2,
	}

	rollingOut := rolledOut
	rollingOut.UpdatedNumberScheduled = 1

	setDaemonSetStatus(t, cl, rollingOut)
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateCreating, spodState(t, cl))

	setDaemonSetStatus(t, cl, rolledOut)
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateRunning, spodState(t, cl))

	degraded := rolledOut
	degraded.NumberAvailable = 1
	degraded.NumberReady = 1

	setDaemonSetStatus(t, cl, degraded)
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateUpdating, spodState(t, cl))

	setDaemonSetStatus(t, cl, rolledOut)
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateRunning, spodState(t, cl))
}

// A deleted metrics service gets restored, even if nothing else changed.
func TestReconcileRestoresMetricsService(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})
	reconcileSPOD(t, r)

	key := types.NamespacedName{Name: "metrics", Namespace: testNamespace}
	service := &corev1.Service{}
	require.NoError(t, cl.Get(t.Context(), key, service))

	stored := &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(spod), stored))
	require.True(t, metav1.IsControlledBy(service, stored))

	require.NoError(t, cl.Delete(t.Context(), service))
	reconcileSPOD(t, r)
	require.NoError(t, cl.Get(t.Context(), key, service))

	// A service of a previous version without owner gets adopted.
	service.OwnerReferences = nil
	require.NoError(t, cl.Update(t.Context(), service))
	reconcileSPOD(t, r)
	require.NoError(t, cl.Get(t.Context(), key, service))
	require.True(t, metav1.IsControlledBy(service, stored))
}

// A missing service monitor gets created on update, while a cluster without
// the ServiceMonitor API is ignored.
func TestPatchOrCreate(t *testing.T) {
	t.Parallel()

	cl := fake.NewClientBuilder().WithScheme(reconcileTestScheme(t)).Build()
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: testNamespace}}

	require.NoError(t, patchOrCreate(t.Context(), cl, service.DeepCopy()))
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(service), &corev1.Service{}))

	service.Labels = map[string]string{"updated": "true"}
	require.NoError(t, patchOrCreate(t.Context(), cl, service.DeepCopy()))

	found := &corev1.Service{}
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(service), found))
	require.Equal(t, "true", found.Labels["updated"])
}

func getSPOD(t *testing.T, cl client.Client) *spodapi.SecurityProfilesOperatorDaemon {
	t.Helper()

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, spod))

	return spod
}

func getDaemonSet(t *testing.T, cl client.Client) *appsv1.DaemonSet {
	t.Helper()

	ds := &appsv1.DaemonSet{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, ds))

	return ds
}

func reconcileRequest() reconcile.Request {
	return reconcile.Request{
		NamespacedName: types.NamespacedName{Name: config.SPOdName, Namespace: testNamespace},
	}
}

// A transient failure to read the operator ConfigMap must not render the
// JSON enricher without its log volume, which would roll every SPOd pod and
// roll them back with the next successful read.
func TestReconcileJsonEnricherConfigMapFailure(t *testing.T) {
	t.Parallel()

	logVolume, err := json.Marshal(&corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}})
	require.NoError(t, err)

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: util.OperatorConfigMap, Namespace: testNamespace},
		Data: map[string]string{
			util.JsonEnricherLogVolumeSourceJson: string(logVolume),
			util.JsonEnricherLogVolumeMountPath:  "/logs",
		},
	}

	spod := testSPOD()
	spod.Spec.Enricher.EnableJsonEnricher = new(true)
	spod.Status.StatePending()

	fail := false
	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{
		Get: func(
			ctx context.Context, c client.WithWatch, key client.ObjectKey,
			obj client.Object, opts ...client.GetOption,
		) error {
			if _, ok := obj.(*corev1.ConfigMap); ok && fail {
				return apierrors.NewServiceUnavailable("test")
			}

			return c.Get(ctx, key, obj, opts...)
		},
	}, configMap)

	reconcileSPOD(t, r)

	before := getDaemonSet(t, cl)
	require.True(
		t,
		slices.ContainsFunc(before.Spec.Template.Spec.Volumes, func(v corev1.Volume) bool {
			return v.Name == "json-enricher-log-output-volume"
		}),
	)

	fail = true

	_, err = r.Reconcile(t.Context(), reconcileRequest())
	require.Error(t, err)

	after := getDaemonSet(t, cl)
	require.Equal(t, before.ResourceVersion, after.ResourceVersion)
	require.Equal(t, before.Spec.Template, after.Spec.Template)

	// The failure is reported in the status of the SPOD.
	stored := getSPOD(t, cl)
	require.Equal(t, spodapi.SPODStateError, stored.Status.State)
	require.Equal(t, stored.Generation, stored.Status.ObservedGeneration)

	ready := stored.Status.GetReadyCondition()
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Contains(t, ready.Message, "JSON enricher log volume")
	require.Equal(t, stored.Generation, ready.ObservedGeneration)

	// The next successful read leaves the DaemonSet alone and the SPOD
	// leaves the error state.
	fail = false

	reconcileSPOD(t, r)
	require.Equal(t, before.Spec.Template, getDaemonSet(t, cl).Spec.Template)
	require.NotEqual(t, spodapi.SPODStateError, spodState(t, cl))
}

// An update which fails after the webhook got updated reports a warning
// event and the error state, except for a conflict, which the next
// reconciliation resolves.
func TestReconcileUpdateFailure(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		patchErr  error
		wantError bool
	}{
		"error":    {patchErr: errTest, wantError: true},
		"conflict": {patchErr: apierrors.NewConflict(appsv1.Resource("daemonsets"), "spod", errTest)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			spod := testSPOD()
			spod.Status.StatePending()

			fail := false
			r, cl, recorder := newReconcileTest(t, spod, &interceptor.Funcs{
				Patch: func(
					ctx context.Context, c client.WithWatch, obj client.Object,
					patch client.Patch, opts ...client.PatchOption,
				) error {
					if _, ok := obj.(*appsv1.DaemonSet); ok && fail {
						return tc.patchErr
					}

					return c.Patch(ctx, obj, patch, opts...)
				},
			})

			reconcileSPOD(t, r)
			before := getDaemonSet(t, cl)

			stored := getSPOD(t, cl)
			stored.Spec.Verbosity = 2
			require.NoError(t, cl.Update(t.Context(), stored))

			fail = true

			res, err := r.Reconcile(t.Context(), reconcileRequest())
			if tc.wantError {
				require.ErrorIs(t, err, tc.patchErr)
			} else {
				// A conflict is retried shortly without an error.
				require.NoError(t, err)
				require.Equal(t, conflictRequeueDelay, res.RequeueAfter)
			}

			require.Equal(t, before.Spec.Template, getDaemonSet(t, cl).Spec.Template)
			require.Equal(t, tc.wantError, spodState(t, cl) == spodapi.SPODStateError)

			var recorded []string

			for len(recorder.Events) > 0 {
				recorded = append(recorded, <-recorder.Events)
			}

			require.Equal(t, tc.wantError, slices.ContainsFunc(recorded, func(e string) bool {
				return strings.Contains(e, reasonCannotUpdateSPOD)
			}), recorded)

			// The update goes through once the DaemonSet can be written.
			fail = false

			reconcileSPOD(t, r)
			require.Equal(t, spodapi.SPODStateUpdating, spodState(t, cl))
			require.NotEqual(t, before.Spec.Template, getDaemonSet(t, cl).Spec.Template)
		})
	}
}

// The status records the generation it was computed for.
func TestReconcileObservedGeneration(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Generation = 3

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})

	reconcileSPOD(t, r)

	stored := getSPOD(t, cl)
	require.Equal(t, spodapi.SPODStatePending, stored.Status.State)
	require.Equal(t, stored.Generation, stored.Status.ObservedGeneration)
	require.Equal(t, stored.Generation, stored.Status.GetReadyCondition().ObservedGeneration)
}

// A spec change which touches neither the DaemonSet nor the webhook still
// gets observed.
func TestReconcileObservedGenerationWithoutOperandChange(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	r, cl, _ := newReconcileTest(t, spod, &interceptor.Funcs{})
	reconcileSPOD(t, r)

	setDaemonSetStatus(t, cl, appsv1.DaemonSetStatus{
		DesiredNumberScheduled: 1,
		UpdatedNumberScheduled: 1,
		NumberAvailable:        1,
		NumberReady:            1,
	})
	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateRunning, spodState(t, cl))

	before := getDaemonSet(t, cl)

	stored := getSPOD(t, cl)
	stored.Spec.Security.AllowedSyscalls = []string{"read", "write"}
	stored.Generation++
	require.NoError(t, cl.Update(t.Context(), stored))

	generation := getSPOD(t, cl).Generation
	require.NotEqual(t, getSPOD(t, cl).Status.ObservedGeneration, generation)

	reconcileSPOD(t, r)

	require.Equal(t, before.Spec.Template, getDaemonSet(t, cl).Spec.Template)

	stored = getSPOD(t, cl)
	require.Equal(t, spodapi.SPODStateRunning, stored.Status.State)
	require.Equal(t, generation, stored.Status.ObservedGeneration)
	require.Equal(t, generation, stored.Status.GetReadyCondition().ObservedGeneration)
}

// reconcileUntilRunning reconciles the SPOD until it reports the running state.
func reconcileUntilRunning(t *testing.T, r *ReconcileSPOd, cl client.Client) {
	t.Helper()

	for range 5 {
		reconcileSPOD(t, r)

		if spodState(t, cl) == spodapi.SPODStateRunning {
			return
		}
	}

	require.Equal(t, spodapi.SPODStateRunning, spodState(t, cl))
}

// countingWrites returns interceptor funcs which count every write. The
// created and updated workloads get the defaults of the API server, see
// applyServerDefaults.
func countingWrites(t *testing.T, writes *atomic.Int32) *interceptor.Funcs {
	t.Helper()

	return &interceptor.Funcs{
		Create: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption,
		) error {
			writes.Add(1)
			applyServerDefaults(t, obj)

			return c.Create(ctx, obj, opts...)
		},
		Update: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
		) error {
			writes.Add(1)
			applyServerDefaults(t, obj)

			return c.Update(ctx, obj, opts...)
		},
		Patch: func(
			ctx context.Context, c client.WithWatch, obj client.Object,
			patch client.Patch, opts ...client.PatchOption,
		) error {
			writes.Add(1)

			return c.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(
			ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption,
		) error {
			writes.Add(1)

			return c.Delete(ctx, obj, opts...)
		},
		SubResourceUpdate: func(
			ctx context.Context, c client.Client, sub string, obj client.Object,
			opts ...client.SubResourceUpdateOption,
		) error {
			writes.Add(1)

			return c.SubResource(sub).Update(ctx, obj, opts...)
		},
		SubResourcePatch: func(
			ctx context.Context, c client.Client, sub string, obj client.Object,
			patch client.Patch, opts ...client.SubResourcePatchOption,
		) error {
			writes.Add(1)

			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}
}

// A running SPOD whose operands match the configuration causes no writes, also
// with the fields which the API server defaults on the workloads.
func TestReconcileSteadyStateIsIdempotent(t *testing.T) {
	t.Parallel()

	for name, static := range map[string]bool{"managed webhook": false, "static webhook": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			spod := testSPOD()
			spod.Spec.Webhook.StaticConfig = new(static)
			spod.Spec.Enricher.EnableJsonEnricher = new(true)

			var writes atomic.Int32

			r, cl, _ := newReconcileTest(
				t,
				spod,
				countingWrites(t, &writes),
				operatorConfigMap(nil),
			)
			reconcileUntilRunning(t, r, cl)

			ctr := getDaemonSet(t, cl).Spec.Template.Spec.Containers[0]
			require.Equal(t, corev1.TerminationMessagePathDefault, ctr.TerminationMessagePath,
				"the DaemonSet carries the defaults of the API server")
			require.NotNil(t, ctr.SecurityContext.ProcMount)

			writes.Store(0)
			reconcileSPOD(t, r)
			reconcileSPOD(t, r)
			require.Zero(t, writes.Load())

			// A static webhook is deployed by the administrator.
			err := cl.Get(t.Context(), types.NamespacedName{
				Name: config.OperatorName + "-webhook", Namespace: testNamespace,
			}, &appsv1.Deployment{})
			require.Equal(t, static, apierrors.IsNotFound(err), err)
		})
	}
}

// The namespaced webhook objects and the cert-manager resources are not owned
// by the SPOD, so that deleting the SPOD keeps the webhook running for the
// webhook configurations which stay behind. Deleted ones get restored.
func TestReconcileRestoresUnownedWebhookObjects(t *testing.T) {
	t.Parallel()

	r, cl, _ := newReconcileTest(t, testSPOD(), &interceptor.Funcs{})
	reconcileUntilRunning(t, r, cl)

	webhookName := config.OperatorName + "-webhook"
	unowned := []client.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "webhook-service"}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: webhookName}},
		&certmanagerv1.Issuer{ObjectMeta: metav1.ObjectMeta{Name: "selfsigned-issuer"}},
		&certmanagerv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "webhook-cert"}},
		&certmanagerv1.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "metrics-cert"}},
	}

	for _, obj := range unowned {
		obj.SetNamespace(testNamespace)
		require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(obj), obj), "%T", obj)
		require.Empty(t, obj.GetOwnerReferences(), "%T", obj)
		require.NoError(t, cl.Delete(t.Context(), obj), "%T", obj)
	}

	reconcileSPOD(t, r)

	for _, obj := range unowned {
		require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(obj), obj), "%T", obj)
	}
}

// A deleted cert-manager resource gets created again by the next update
// instead of failing every update of the SPOD.
func TestReconcileRecreatesDeletedCertificate(t *testing.T) {
	t.Parallel()

	r, cl, _ := newReconcileTest(t, testSPOD(), &interceptor.Funcs{})
	reconcileUntilRunning(t, r, cl)

	cert := &certmanagerv1.Certificate{ObjectMeta: metav1.ObjectMeta{
		Name: "webhook-cert", Namespace: testNamespace,
	}}
	require.NoError(t, cl.Delete(t.Context(), cert))

	stored := getSPOD(t, cl)
	stored.Spec.Verbosity = 1
	require.NoError(t, cl.Update(t.Context(), stored))

	reconcileSPOD(t, r)
	require.Equal(t, spodapi.SPODStateUpdating, spodState(t, cl))
	require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(cert), cert))
}

// Webhook options which weaken the binding webhook are applied with a warning.
func TestReconcileWarnsAboutWeakenedBinding(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Spec.Webhook.Options = []spodapi.WebhookOptions{{
		Name:          "binding.spo.io",
		FailurePolicy: new(admissionregv1.Ignore),
	}}

	r, cl, recorder := newReconcileTest(t, spod, &interceptor.Funcs{})
	reconcileUntilRunning(t, r, cl)

	var recorded []string

	for len(recorder.Events) > 0 {
		recorded = append(recorded, <-recorder.Events)
	}

	require.True(t, slices.ContainsFunc(recorded, func(e string) bool {
		return strings.Contains(e, reasonWeakenedBindingWebhook)
	}), recorded)

	hooks := &admissionregv1.MutatingWebhookConfiguration{}
	require.NoError(t, cl.Get(t.Context(), types.NamespacedName{
		Name: bindata.MutatingWebhookConfigName,
	}, hooks))
	require.Equal(t, admissionregv1.Ignore, *hooks.Webhooks[0].FailurePolicy)
}
