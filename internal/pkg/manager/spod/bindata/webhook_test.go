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
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const testLabel = "test"

func TestNamespaceSelectorUnequalForLabel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		existing, configured *metav1.LabelSelector
		expected             bool
	}{
		{
			name:       "label not available in both selectors",
			existing:   &metav1.LabelSelector{},
			configured: &metav1.LabelSelector{},
			expected:   false,
		},
		{
			name: "label requirements are equal",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"foo"},
				},
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"foo"},
				},
			}},
			expected: false,
		},
		{
			name: "label requirements are not equal in value",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"foo"},
				},
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"bar"},
				},
			}},
			expected: true,
		},
		{
			name:     "label requirements are not equal (existing does not have the expression)",
			existing: &metav1.LabelSelector{},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"bar"},
				},
			}},
			expected: true,
		},
		{
			name: "label requirements are not equal (configured does not have the expression)",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"bar"},
				},
			}},
			configured: &metav1.LabelSelector{},
			expected:   true,
		},
		{
			// A user expression for the same key as the operator namespace
			// exclusion must not hide that the exclusion is missing.
			name: "label requirements are not equal (configured has an additional expression)",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"foo"},
				},
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"foo"},
				},
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"bar"},
				},
			}},
			expected: true,
		},
	} {
		existing := tc.existing
		configured := tc.configured
		expected := tc.expected

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := namespaceSelectorUnequalForLabel(testLabel, existing, configured)
			assert.Equal(t, expected, res)
		})
	}
}

func TestWebhook_NeedsUpdate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		existing, configured *admissionregv1.MutatingWebhook
		expected             bool
	}{
		{
			name:       "label not available in both selectors",
			existing:   &admissionregv1.MutatingWebhook{},
			configured: &admissionregv1.MutatingWebhook{},
			expected:   false,
		},
		{
			name: "Some content in object select and empty",
			existing: &admissionregv1.MutatingWebhook{
				Name: "foo",
				ObjectSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      testLabel,
							Operator: metav1.LabelSelectorOpExists,
							Values:   []string{"val"},
						},
					},
				},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			expected: true,
		},
		{
			name: "Empty existing and nil. Required to handle defaults",
			existing: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: nil,
			},
			expected: false,
		},
		{
			name: "Nil existing and empty",
			existing: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: nil,
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			expected: true,
		},
		{
			name: "Nil existing and empty",
			existing: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: nil,
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: &metav1.LabelSelector{},
			},
			expected: true,
		},
		{
			// Otherwise a cluster set up before the exclusion existed would
			// never receive it.
			name: "operator namespace exclusion missing",
			existing: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: requireLabel(EnableBindingLabel),
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: excludeOperatorNamespace(EnableBindingLabel, "spo"),
			},
			expected: true,
		},
		{
			name: "existing empty and nil",
			existing: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: &metav1.LabelSelector{},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: nil,
			},
			expected: false,
		},
	} {
		existing := tc.existing
		configured := tc.configured
		expected := tc.expected
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := Webhook{
				log: logr.Discard(),
				config: &admissionregv1.MutatingWebhookConfiguration{
					Webhooks: []admissionregv1.MutatingWebhook{
						*configured,
					},
				},
			}
			requireUpdate := w.webhookNeedsUpdate(existing, 0)
			assert.Equal(t, expected, requireUpdate)
		})
	}
}

func TestWebhook_getWebhookConfig(t *testing.T) {
	t.Parallel()

	webhookConfig := getWebhookConfig(false, "custom-operator-ns")
	require.Len(t, webhookConfig.Webhooks, 2)

	// Binding is a security boundary, so the operator's namespace is excluded by
	// the namespace the controller actually runs in rather than by a pod label a
	// pod author could claim, and not by a guessed default namespace either.
	bindingHook := webhookConfig.Webhooks[binding.index]
	require.NotNil(t, bindingHook.NamespaceSelector)
	assert.Nil(t, bindingHook.ObjectSelector)

	var excluded []string

	for _, expr := range bindingHook.NamespaceSelector.MatchExpressions {
		if expr.Key == corev1.LabelMetadataName {
			assert.Equal(t, metav1.LabelSelectorOpNotIn, expr.Operator)

			excluded = expr.Values
		}
	}

	assert.Equal(t, []string{"custom-operator-ns"}, excluded)

	// Recording is not a security boundary and has to keep working for
	// workloads that run in the operator's namespace, so only the operator's own
	// pods are kept out, by label.
	recordingHook := webhookConfig.Webhooks[recording.index]
	require.NotNil(t, recordingHook.NamespaceSelector)

	for _, expr := range recordingHook.NamespaceSelector.MatchExpressions {
		assert.NotEqual(t, corev1.LabelMetadataName, expr.Key,
			"recording must not be disabled for the operator namespace")
	}

	require.NotNil(t, recordingHook.ObjectSelector)
	require.Len(t, recordingHook.ObjectSelector.MatchExpressions, 1)
	excludedPods := recordingHook.ObjectSelector.MatchExpressions[0]
	assert.Equal(t, metav1.LabelSelectorOpNotIn, excludedPods.Operator)
	assert.Contains(t, excludedPods.Values, config.OperatorName)

	// Both still require the namespace to opt in.
	for _, wh := range webhookConfig.Webhooks {
		require.NotNil(t, wh.NamespaceSelector)
		assert.NotEmpty(t, wh.NamespaceSelector.MatchExpressions)
	}

	bindingOps := webhookConfig.Webhooks[binding.index].Rules[0].Operations
	assert.ElementsMatch(t, []admissionregv1.OperationType{"CREATE"}, bindingOps)

	recordingOps := webhookConfig.Webhooks[recording.index].Rules[0].Operations
	assert.ElementsMatch(
		t,
		[]admissionregv1.OperationType{"CREATE", "UPDATE"},
		recordingOps,
	)

	webhookConfig = getWebhookConfig(true, "custom-operator-ns")
	require.Len(t, webhookConfig.Webhooks, 4)
}

// TestApplyWebhookOptionsKeepsOperatorNamespaceExcluded covers a custom binding
// namespace selector. It used to replace the whole selector and with it the
// operator namespace exclusion, so binding applied to the operator's own pods.
func TestApplyWebhookOptionsKeepsOperatorNamespaceExcluded(t *testing.T) {
	t.Parallel()

	const operatorNamespace = "custom-operator-ns"

	userSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "team",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"a"},
		}},
	}

	cfg := getWebhookConfig(false, operatorNamespace)
	applyWebhookOptions(cfg, []spodapi.WebhookOptions{
		{Name: binding.name, NamespaceSelector: userSelector},
		{Name: recording.name, NamespaceSelector: userSelector},
	}, operatorNamespace)

	assert.Equal(t, []metav1.LabelSelectorRequirement{
		userSelector.MatchExpressions[0],
		{
			Key:      corev1.LabelMetadataName,
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{operatorNamespace},
		},
	}, cfg.Webhooks[binding.index].NamespaceSelector.MatchExpressions)

	// Recording deliberately has no namespace exclusion.
	assert.Equal(t, userSelector.MatchExpressions,
		cfg.Webhooks[recording.index].NamespaceSelector.MatchExpressions)

	// The user's options stay untouched.
	assert.Len(t, userSelector.MatchExpressions, 1)

	// A user selector that already excludes the operator namespace does not
	// get a duplicate expression.
	excluding := excludeOperatorNamespace(EnableBindingLabel, operatorNamespace)
	cfg = getWebhookConfig(false, operatorNamespace)
	applyWebhookOptions(cfg, []spodapi.WebhookOptions{
		{Name: binding.name, NamespaceSelector: excluding},
	}, operatorNamespace)
	assert.Equal(t, excluding.MatchExpressions,
		cfg.Webhooks[binding.index].NamespaceSelector.MatchExpressions)
}

func TestWebhook_DeploymentSecurityContext(t *testing.T) {
	t.Parallel()

	sut := GetWebhook(
		logr.Discard(), "test-ns", nil, "image", corev1.PullAlways,
		CAInjectTypeCertManager, nil, nil, false,
	)

	podSpec := sut.deployment.Spec.Template.Spec
	require.NotNil(t, podSpec.SecurityContext)
	require.NotNil(t, podSpec.SecurityContext.SeccompProfile)
	assert.Equal(
		t,
		corev1.SeccompProfileTypeRuntimeDefault,
		podSpec.SecurityContext.SeccompProfile.Type,
	)

	require.Len(t, podSpec.Containers, 1)
	sc := podSpec.Containers[0].SecurityContext
	require.NotNil(t, sc)
	require.NotNil(t, sc.AllowPrivilegeEscalation)
	assert.False(t, *sc.AllowPrivilegeEscalation)
	require.NotNil(t, sc.ReadOnlyRootFilesystem)
	assert.True(t, *sc.ReadOnlyRootFilesystem)
	require.NotNil(t, sc.RunAsNonRoot)
	assert.True(t, *sc.RunAsNonRoot)
	require.NotNil(t, sc.Capabilities)
	assert.Equal(t, []corev1.Capability{"ALL"}, sc.Capabilities.Drop)
	assert.Empty(t, sc.Capabilities.Add)
}

func TestWebhook_getWebhookConfigHardening(t *testing.T) {
	t.Parallel()

	webhookConfig := getWebhookConfig(true, "custom-operator-ns")

	for _, wh := range webhookConfig.Webhooks {
		require.NotNil(t, wh.TimeoutSeconds)
		assert.Equal(t, int32(10), *wh.TimeoutSeconds, wh.Name)
	}

	// Ephemeral containers must not escape the binding.
	bindingRules := webhookConfig.Webhooks[binding.index].Rules
	require.Len(t, bindingRules, 2)
	assert.Equal(t, []string{"pods/ephemeralcontainers"}, bindingRules[1].Resources)
	assert.Equal(t, []admissionregv1.OperationType{"UPDATE"}, bindingRules[1].Operations)

	// Execs into system namespaces are not rewritten.
	execHook := webhookConfig.Webhooks[execMetadata.index]
	require.NotNil(t, execHook.NamespaceSelector)
	require.Len(t, execHook.NamespaceSelector.MatchExpressions, 1)

	expr := execHook.NamespaceSelector.MatchExpressions[0]
	assert.Equal(t, corev1.LabelMetadataName, expr.Key)
	assert.Equal(t, metav1.LabelSelectorOpNotIn, expr.Operator)
	assert.Contains(t, expr.Values, metav1.NamespaceSystem)
	assert.Contains(t, expr.Values, "custom-operator-ns")
}

// Rules and timeouts are not tunable, but change between releases, so an
// existing configuration of an older release has to be updated.
func TestWebhook_NeedsUpdateRulesAndTimeouts(t *testing.T) {
	t.Parallel()

	configured := getWebhookConfig(false, "ns")
	w := Webhook{log: logr.Discard(), config: configured}

	existing := configured.Webhooks[binding.index].DeepCopy()
	assert.False(t, w.webhookNeedsUpdate(existing, binding.index))

	existing.TimeoutSeconds = new(int32(30))
	assert.True(t, w.webhookNeedsUpdate(existing, binding.index))

	existing = configured.Webhooks[binding.index].DeepCopy()
	existing.Rules = existing.Rules[:1]
	assert.True(t, w.webhookNeedsUpdate(existing, binding.index))
}

func TestWebhook_DeploymentRequiredSCC(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "restricted-v2",
		webhookDeployment.Spec.Template.Annotations[openshiftRequiredSCCAnnotation])
	assert.Equal(t, "privileged",
		Manifest.Spec.Template.Annotations[openshiftRequiredSCCAnnotation])
}

func newTestWebhook(t *testing.T, tolerations []corev1.Toleration) *Webhook {
	t.Helper()

	return GetWebhook(
		logr.Discard(), "spo-ns", nil, "image", corev1.PullAlways,
		CAInjectTypeCertManager, tolerations, nil, false,
	)
}

func TestWebhook_CertManagerAnnotationUsesNamespace(t *testing.T) {
	t.Parallel()

	w := newTestWebhook(t, nil)

	assert.Equal(t, "spo-ns/webhook-cert", w.config.Annotations[certManagerInjectAnnotation])
	assert.Equal(
		t,
		"spo-ns/webhook-cert",
		w.validatingConfig.Annotations[certManagerInjectAnnotation],
	)
}

// The binding and recording webhooks record events, which they skip for dry
// run requests.
func TestWebhook_SideEffects(t *testing.T) {
	t.Parallel()

	cfg := getWebhookConfig(true, "ns")
	for _, hook := range []webhook{binding, recording} {
		assert.Equal(t, admissionregv1.SideEffectClassNoneOnDryRun,
			*cfg.Webhooks[hook.index].SideEffects, hook.name)
	}

	w := Webhook{log: logr.Discard(), config: cfg}
	existing := cfg.Webhooks[binding.index].DeepCopy()
	existing.SideEffects = &sideEffects
	assert.True(t, w.webhookNeedsUpdate(existing, binding.index))
}

func TestWebhook_DeploymentAvailability(t *testing.T) {
	t.Parallel()

	w := newTestWebhook(t, nil)
	podSpec := w.deployment.Spec.Template.Spec

	probe := podSpec.Containers[0].ReadinessProbe
	require.NotNil(t, probe)
	require.NotNil(t, probe.HTTPGet)
	assert.Equal(t, "/readyz", probe.HTTPGet.Path)
	assert.Equal(t, int32(config.HealthProbePort), probe.HTTPGet.Port.IntVal)

	require.NotNil(t, podSpec.Affinity)
	require.NotNil(t, podSpec.Affinity.PodAntiAffinity)
	terms := podSpec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution
	require.Len(t, terms, 1)
	assert.Equal(t, w.deployment.Spec.Selector, terms[0].PodAffinityTerm.LabelSelector)
}

func webhookTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// The API server fills in defaults when it stores the deployment, which must
// not make the deployment look outdated forever.
func TestDeploymentNeedsUpdateIgnoresServerDefaults(t *testing.T) {
	t.Parallel()

	w := newTestWebhook(t, nil)
	stored := w.deployment.DeepCopy()

	podSpec := &stored.Spec.Template.Spec
	podSpec.RestartPolicy = corev1.RestartPolicyAlways
	podSpec.DNSPolicy = corev1.DNSClusterFirst
	podSpec.SchedulerName = corev1.DefaultSchedulerName
	podSpec.TerminationGracePeriodSeconds = ptr.To[int64](30)

	for i := range podSpec.Containers {
		ctr := &podSpec.Containers[i]
		ctr.TerminationMessagePath = corev1.TerminationMessagePathDefault
		ctr.TerminationMessagePolicy = corev1.TerminationMessageReadFile

		if probe := ctr.ReadinessProbe; probe != nil {
			probe.TimeoutSeconds = 1
			probe.PeriodSeconds = 10
			probe.SuccessThreshold = 1
			probe.FailureThreshold = 3
			probe.HTTPGet.Scheme = corev1.URISchemeHTTP
		}
	}

	assert.False(t, deploymentNeedsUpdate(w.deployment, stored))
}

// A missing configuration must not block the reconciliation, it gets created
// again.
func TestWebhook_UpdateCreatesMissingObjects(t *testing.T) {
	t.Parallel()

	w := newTestWebhook(t, nil)
	c := webhookTestClient(t)
	ctx := t.Context()

	needsUpdate, err := w.NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.True(t, needsUpdate)

	require.NoError(t, w.Update(ctx, c))

	for _, obj := range []client.Object{
		&admissionregv1.MutatingWebhookConfiguration{},
		&admissionregv1.ValidatingWebhookConfiguration{},
		&appsv1.Deployment{},
		&corev1.Service{},
	} {
		var key client.ObjectKey

		switch obj.(type) {
		case *admissionregv1.MutatingWebhookConfiguration:
			key = client.ObjectKeyFromObject(w.config)
		case *admissionregv1.ValidatingWebhookConfiguration:
			key = client.ObjectKeyFromObject(w.validatingConfig)
		case *appsv1.Deployment:
			key = client.ObjectKeyFromObject(w.deployment)
		case *corev1.Service:
			key = client.ObjectKeyFromObject(w.service)
		}

		require.NoError(t, c.Get(ctx, key, obj), "%T", obj)
	}

	needsUpdate, err = newTestWebhook(t, nil).NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.False(t, needsUpdate)
}

// The CA bundle gets injected into the configurations after they got
// created, so writing the configured placeholder would break the webhooks.
func TestWebhook_UpdateKeepsInjectedCABundle(t *testing.T) {
	t.Parallel()

	injected := []byte("injected")
	c := webhookTestClient(t)
	ctx := t.Context()

	require.NoError(t, newTestWebhook(t, nil).Create(ctx, c))

	mutating := &admissionregv1.MutatingWebhookConfiguration{}
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: webhookConfigName}, mutating))

	for i := range mutating.Webhooks {
		mutating.Webhooks[i].ClientConfig.CABundle = injected
	}

	require.NoError(t, c.Update(ctx, mutating))

	validating := &admissionregv1.ValidatingWebhookConfiguration{}
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: validatingWebhookConfigName}, validating))
	validating.Webhooks[0].ClientConfig.CABundle = injected
	require.NoError(t, c.Update(ctx, validating))

	// Both an update and a create of existing configurations keep the bundle.
	require.NoError(t, newTestWebhook(t, nil).Update(ctx, c))
	require.NoError(t, newTestWebhook(t, nil).Create(ctx, c))

	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: webhookConfigName}, mutating))

	for i := range mutating.Webhooks {
		assert.Equal(t, injected, mutating.Webhooks[i].ClientConfig.CABundle)
	}

	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: validatingWebhookConfigName}, validating))
	assert.Equal(t, injected, validating.Webhooks[0].ClientConfig.CABundle)
}

// Changes of the deployment, like cleared tolerations, have to be detected
// and applied.
func TestWebhook_DeploymentUpdate(t *testing.T) {
	t.Parallel()

	custom := []corev1.Toleration{{Key: "custom", Operator: corev1.TolerationOpExists}}
	c := webhookTestClient(t)
	ctx := t.Context()

	require.NoError(t, newTestWebhook(t, custom).Create(ctx, c))

	w := newTestWebhook(t, nil)

	needsUpdate, err := w.NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.True(t, needsUpdate)

	require.NoError(t, w.Update(ctx, c))

	deployment := &appsv1.Deployment{}
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(w.deployment), deployment))
	assert.Equal(t, webhookDeployment.Spec.Template.Spec.Tolerations,
		deployment.Spec.Template.Spec.Tolerations)

	needsUpdate, err = newTestWebhook(t, nil).NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.False(t, needsUpdate)

	// An image change is detected as well.
	image := GetWebhook(
		logr.Discard(), "spo-ns", nil, "new-image", corev1.PullAlways,
		CAInjectTypeCertManager, nil, nil, false,
	)
	needsUpdate, err = image.NeedsUpdate(ctx, c)
	require.NoError(t, err)
	require.True(t, needsUpdate)
}
