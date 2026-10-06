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

package bindata

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var errTest = errors.New("test")

func TestGetCAInjectType(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, configv1.AddToScheme(scheme))

	openShift := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "openshift-apiserver"},
	}

	got, err := GetCAInjectType(t.Context(), logr.Discard(),
		fake.NewClientBuilder().WithScheme(scheme).WithObjects(openShift).Build())
	require.NoError(t, err)
	require.Equal(t, CAInjectTypeOpenShift, got)

	got, err = GetCAInjectType(t.Context(), logr.Discard(),
		fake.NewClientBuilder().WithScheme(scheme).Build())
	require.NoError(t, err)
	require.Equal(t, CAInjectTypeCertManager, got)

	// A cluster without the OpenShift config API is not OpenShift either.
	got, err = GetCAInjectType(t.Context(), logr.Discard(),
		fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build())
	require.NoError(t, err)
	require.Equal(t, CAInjectTypeCertManager, got)

	failing := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errTest
		},
	}).Build()
	_, err = GetCAInjectType(t.Context(), logr.Discard(), failing)
	require.ErrorIs(t, err, errTest)
}

func TestServiceMonitor(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		namespace  string
		caType     CAInjectType
		insecure   bool
		wantScheme monitoringv1.Scheme
		wantCAFile bool
	}{
		"cert-manager": {
			namespace: "spo", caType: CAInjectTypeCertManager, wantScheme: "https",
		},
		"insecure": {
			namespace: "spo", caType: CAInjectTypeCertManager, insecure: true, wantScheme: "http",
		},
		"openshift outside an openshift namespace": {
			namespace: "spo", caType: CAInjectTypeOpenShift, wantScheme: "https",
		},
		"openshift system install": {
			namespace: "openshift-security-profiles", caType: CAInjectTypeOpenShift,
			wantScheme: "https", wantCAFile: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sm := ServiceMonitor(tc.namespace, tc.caType, tc.insecure)
			require.Equal(t, tc.namespace, sm.Namespace)
			require.Len(t, sm.Spec.Endpoints, 2)
			require.Equal(t, "/metrics", sm.Spec.Endpoints[0].Path)
			require.Equal(t, "/metrics-spod", sm.Spec.Endpoints[1].Path)

			for _, ep := range sm.Spec.Endpoints {
				require.Equal(t, tc.wantScheme, *ep.Scheme)

				if tc.insecure {
					require.Equal(t, "http", ep.Port)
					require.Nil(t, ep.Authorization)
					require.Nil(t, ep.TLSConfig)

					continue
				}

				require.Equal(t, "https", ep.Port)
				require.NotNil(t, ep.Authorization)
				require.Equal(t, "spo-metrics-client-token", ep.Authorization.Credentials.Name)
				require.NotNil(t, ep.TLSConfig)
				require.Equal(t, "metrics."+tc.namespace+".svc", *ep.TLSConfig.ServerName)

				if tc.wantCAFile {
					require.NotEmpty(t, ep.TLSConfig.CAFile)
					require.Nil(t, ep.TLSConfig.CA.Secret)
				} else {
					require.Empty(t, ep.TLSConfig.CAFile)
					require.Equal(t, metricsServerCert, ep.TLSConfig.CA.Secret.Name)
				}
			}
		})
	}
}

func TestDefaultLogEnricherProfile(t *testing.T) {
	t.Parallel()

	profile := DefaultLogEnricherProfile()
	require.Equal(t, config.LogEnricherProfile, profile.Name)
	require.Empty(t, profile.Namespace, "seccomp profiles are cluster scoped")
	require.Equal(t, config.OperatorName, profile.Labels[labelApp])
	require.Equal(t, seccompprofileapi.ActLog, profile.Spec.DefaultAction)

	// Every call returns a new object, so callers can modify it.
	profile.Labels["changed"] = "true"
	require.NotContains(t, DefaultLogEnricherProfile().Labels, "changed")
}

func TestNamespaceSelectorExpression(t *testing.T) {
	t.Parallel()

	const labels = "namespaceObject.metadata.labels"

	for name, tc := range map[string]struct {
		selector *metav1.LabelSelector
		want     string
	}{
		"nil":   {want: "true"},
		"empty": {selector: &metav1.LabelSelector{}, want: "true"},
		"match labels sorted": {
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"b": "2", "a": "1"}},
			want: `((has(` + labels + `) && "a" in ` + labels + `) && ` + labels + `["a"] in ["1"]) && ` +
				`((has(` + labels + `) && "b" in ` + labels + `) && ` + labels + `["b"] in ["2"])`,
		},
		"in": {
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "k", Operator: metav1.LabelSelectorOpIn, Values: []string{"x", "y"}},
			}},
			want: `((has(` + labels + `) && "k" in ` + labels + `) && ` + labels + `["k"] in ["x", "y"])`,
		},
		"not in": {
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "k", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"x"}},
			}},
			want: `!((has(` + labels + `) && "k" in ` + labels + `) && ` + labels + `["k"] in ["x"])`,
		},
		"exists": {
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "k", Operator: metav1.LabelSelectorOpExists},
			}},
			want: `(has(` + labels + `) && "k" in ` + labels + `)`,
		},
		"does not exist": {
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "k", Operator: metav1.LabelSelectorOpDoesNotExist},
			}},
			want: `!(has(` + labels + `) && "k" in ` + labels + `)`,
		},
		"quotes are escaped": {
			selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k": `a"b`}},
			want:     `((has(` + labels + `) && "k" in ` + labels + `) && ` + labels + `["k"] in ["a\"b"])`,
		},
		"invalid operator matches nothing": {
			selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "k", Operator: "Invalid"},
			}},
			want: "false",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, namespaceSelectorExpression(tc.selector))
		})
	}
}

func TestGetValidatingWebhookConfig(t *testing.T) {
	t.Parallel()

	cfg := getValidatingWebhookConfig()
	require.Equal(t, ValidatingWebhookConfigName, cfg.Name)
	require.Len(t, cfg.Webhooks, 1)

	hook := cfg.Webhooks[0]
	require.Equal(t, rawSelinuxProfileValidation, hook.Name)
	require.Equal(t, admissionregv1.Fail, *hook.FailurePolicy)
	require.Equal(t, admissionregv1.SideEffectClassNone, *hook.SideEffects)
	require.Equal(t, rawSelinuxProfileWebhookPath, *hook.ClientConfig.Service.Path)
	require.Equal(t, serviceName, hook.ClientConfig.Service.Name)
	require.Equal(t, []string{"rawselinuxprofiles"}, hook.Rules[0].Resources)
	require.ElementsMatch(t,
		[]admissionregv1.OperationType{"CREATE", "UPDATE"}, hook.Rules[0].Operations)

	// Every call returns a new object.
	hook.Name = "changed"
	require.Equal(t, rawSelinuxProfileValidation, getValidatingWebhookConfig().Webhooks[0].Name)
}

func TestKeepCABundles(t *testing.T) {
	t.Parallel()

	injected := []byte("injected")

	mutating := getWebhookConfig(false, "ns")
	existingMutating := mutating.DeepCopy()
	existingMutating.Webhooks[binding.index].ClientConfig.CABundle = injected
	// A webhook without an injected bundle keeps the configured placeholder.
	existingMutating.Webhooks[recording.index].ClientConfig.CABundle = nil

	validating := getValidatingWebhookConfig()
	existingValidating := validating.DeepCopy()
	existingValidating.Webhooks[0].ClientConfig.CABundle = injected

	c := webhookTestClient(t, existingMutating, existingValidating)

	require.NoError(t, keepCABundles(t.Context(), c, mutating))
	require.Equal(t, injected, mutating.Webhooks[binding.index].ClientConfig.CABundle)
	require.Equal(t, caBundle, mutating.Webhooks[recording.index].ClientConfig.CABundle)

	require.NoError(t, keepCABundles(t.Context(), c, validating))
	require.Equal(t, injected, validating.Webhooks[0].ClientConfig.CABundle)

	// Missing configurations keep the placeholder.
	empty := webhookTestClient(t)
	mutating = getWebhookConfig(false, "ns")
	require.NoError(t, keepCABundles(t.Context(), empty, mutating))
	require.Equal(t, caBundle, mutating.Webhooks[binding.index].ClientConfig.CABundle)

	validating = getValidatingWebhookConfig()
	require.NoError(t, keepCABundles(t.Context(), empty, validating))
	require.Equal(t, caBundle, validating.Webhooks[0].ClientConfig.CABundle)
}

func TestWebhook_PodDisruptionBudget(t *testing.T) {
	t.Parallel()

	w := newTestWebhook(t, nil)
	require.Equal(t, "spo-ns", w.pdb.Namespace)
	require.Equal(t, new(intstr.FromInt32(1)), w.pdb.Spec.MinAvailable)
	// The budget covers exactly the webhook replicas.
	require.Equal(t, w.deployment.Spec.Selector, w.pdb.Spec.Selector)
	require.Contains(t, w.objectMap(), "pdb")

	c := webhookTestClient(t)
	ctx := t.Context()
	require.NoError(t, w.Create(ctx, c))

	pdb := &policyv1.PodDisruptionBudget{}
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(w.pdb), pdb))

	needsUpdate, err := newTestWebhook(t, nil).NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.False(t, needsUpdate)

	// A changed budget gets restored.
	pdb.Spec.MinAvailable = new(intstr.FromInt32(0))
	require.NoError(t, c.Update(ctx, pdb))

	needsUpdate, err = newTestWebhook(t, nil).NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.True(t, needsUpdate)

	require.NoError(t, newTestWebhook(t, nil).Update(ctx, c))
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(w.pdb), pdb))
	require.Equal(t, 1, pdb.Spec.MinAvailable.IntValue())

	// A deleted budget gets recreated.
	require.NoError(t, c.Delete(ctx, pdb))

	needsUpdate, err = newTestWebhook(t, nil).NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.True(t, needsUpdate)
}

// containersByName returns the init containers and containers of the SPOd
// manifest by name.
func containersByName() map[string]*corev1.Container {
	podSpec := &Manifest.Spec.Template.Spec
	res := map[string]*corev1.Container{}

	for _, containers := range [][]corev1.Container{podSpec.InitContainers, podSpec.Containers} {
		for i := range containers {
			res[containers[i].Name] = &containers[i]
		}
	}

	return res
}

func mountsVolume(ctr *corev1.Container, volume string) bool {
	return slices.ContainsFunc(ctr.VolumeMounts, func(m corev1.VolumeMount) bool {
		return m.Name == volume
	})
}

// Only the containers which talk to the API server get the service account
// token, all others run without it.
func TestManifestServiceAccountToken(t *testing.T) {
	t.Parallel()

	podSpec := &Manifest.Spec.Template.Spec
	require.False(t, ptr.Deref(podSpec.AutomountServiceAccountToken, true))
	require.True(t, slices.ContainsFunc(podSpec.Volumes, func(v corev1.Volume) bool {
		return v.Name == ServiceAccountTokenVolumeName && v.Projected != nil
	}))

	withToken := []string{
		NonRootEnablerContainerName, config.OperatorName, LogEnricherContainerName,
		BpfRecorderContainerName, JsonEnricherContainerName,
	}

	for name, ctr := range containersByName() {
		require.Equal(t, slices.Contains(withToken, name),
			mountsVolume(ctr, ServiceAccountTokenVolumeName), name)
	}

	volume, mount := ServiceAccountTokenVolume()
	require.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount", mount.MountPath)
	require.True(t, mount.ReadOnly)
	require.Len(t, volume.Projected.Sources, 3)
	require.NotNil(t, volume.Projected.Sources[0].ServiceAccountToken)
	require.Equal(t, "kube-root-ca.crt", volume.Projected.Sources[1].ConfigMap.Name)
	require.Equal(t, "metadata.namespace",
		volume.Projected.Sources[2].DownwardAPI.Items[0].FieldRef.FieldPath)
}

// The enrichers and the recorder run unprivileged with the capabilities they
// use, so that their seccomp profiles are applied as well.
func TestManifestRecorderCapabilities(t *testing.T) {
	t.Parallel()

	containers := containersByName()

	for name, want := range map[string][]corev1.Capability{
		LogEnricherContainerName: {"SYS_PTRACE", "DAC_READ_SEARCH", "CHOWN"},
		BpfRecorderContainerName: {
			"BPF", "PERFMON", "SYS_RESOURCE", "SYS_PTRACE", "DAC_READ_SEARCH", "CHOWN",
		},
		JsonEnricherContainerName: {
			"SYS_PTRACE", "SYS_RESOURCE", "BPF", "PERFMON", "DAC_READ_SEARCH",
		},
	} {
		sc := containers[name].SecurityContext
		require.False(t, ptr.Deref(sc.Privileged, true), name)
		require.True(t, ptr.Deref(sc.ReadOnlyRootFilesystem, false), name)
		require.Equal(t, []corev1.Capability{"ALL"}, sc.Capabilities.Drop, name)
		require.ElementsMatch(t, want, sc.Capabilities.Add, name)
	}

	// The OCI runtime applies the localhost seccomp profile of the recorder
	// only after switching the user with no_new_privs.
	require.False(t, ptr.Deref(
		containers[BpfRecorderContainerName].SecurityContext.AllowPrivilegeEscalation, true,
	))

	// The non-root enabler does not need to keep set-user-ID bits.
	nonRootEnabler := containers[NonRootEnablerContainerName].SecurityContext
	require.NotContains(t, nonRootEnabler.Capabilities.Add, corev1.Capability("FSETID"))
}

// The bpf recorder only mounts what it reads.
func TestManifestBpfRecorderMounts(t *testing.T) {
	t.Parallel()

	recorder := containersByName()[BpfRecorderContainerName]
	require.False(t, mountsVolume(recorder, "tmp-volume"))
	require.False(t, mountsVolume(recorder, "host-etc-osrelease-volume"))

	for _, v := range Manifest.Spec.Template.Spec.Volumes {
		if v.HostPath != nil {
			require.NotEqual(t, "/etc/os-release", v.HostPath.Path)
		}
	}
}
