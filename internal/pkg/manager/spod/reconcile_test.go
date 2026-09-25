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
	"errors"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	t.Setenv(config.OperatorNamespaceEnvKey, testNamespace)

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
	t.Setenv(config.OperatorNamespaceEnvKey, testNamespace)

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
	t.Setenv(config.OperatorNamespaceEnvKey, testNamespace)

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

func TestReconcileWithoutOperatorDeployment(t *testing.T) {
	t.Parallel()

	spod := testSPOD()
	spod.Status.StatePending()

	scheme := reconcileTestScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(spod).Build()
	r := &ReconcileSPOd{client: cl, log: logf.Log, namespace: testNamespace}

	reconcileSPOD(t, r)

	require.Error(t, cl.Get(t.Context(), types.NamespacedName{
		Name: config.SPOdName, Namespace: testNamespace,
	}, &appsv1.DaemonSet{}))
}

func TestReconcileMissingSPOD(t *testing.T) {
	t.Parallel()

	cl := fake.NewClientBuilder().WithScheme(reconcileTestScheme(t)).Build()
	r := &ReconcileSPOd{client: cl, log: logf.Log, namespace: testNamespace}

	reconcileSPOD(t, r)
}

func TestServesAdmissionPolicies(t *testing.T) {
	t.Parallel()

	mapper := meta.NewDefaultRESTMapper(nil)
	require.False(t, servesAdmissionPolicies(mapper))

	mapper.Add(
		admissionregv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicy"),
		meta.RESTScopeRoot,
	)
	require.True(t, servesAdmissionPolicies(mapper))
}
