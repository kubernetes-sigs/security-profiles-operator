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
	"slices"
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

func TestSelectorsEqual(t *testing.T) {
	t.Parallel()

	expr := func(key string, op metav1.LabelSelectorOperator, values ...string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: key, Operator: op, Values: values}
	}

	for _, tc := range []struct {
		name                 string
		existing, configured *metav1.LabelSelector
		expected             bool
	}{
		{name: "both nil", expected: true},
		{name: "nil and empty", configured: &metav1.LabelSelector{}, expected: true},
		{
			name:       "empty maps and slices",
			existing:   &metav1.LabelSelector{MatchLabels: map[string]string{}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{}},
			expected:   true,
		},
		{
			name: "expression order does not matter",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				expr("a", metav1.LabelSelectorOpExists), expr("b", metav1.LabelSelectorOpIn, "y", "x"),
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				expr("b", metav1.LabelSelectorOpIn, "x", "y"), expr("a", metav1.LabelSelectorOpExists),
			}},
			expected: true,
		},
		{
			name:     "match labels changed",
			existing: &metav1.LabelSelector{MatchLabels: map[string]string{testLabel: "a"}},
			configured: &metav1.LabelSelector{
				MatchLabels: map[string]string{testLabel: "b"},
			},
		},
		{
			name: "expression value changed",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				expr(testLabel, metav1.LabelSelectorOpIn, "foo"),
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				expr(testLabel, metav1.LabelSelectorOpIn, "bar"),
			}},
		},
		{
			// A user expression for the same key as the operator namespace
			// exclusion must not hide that the exclusion is missing.
			name: "additional expression for the same key",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				expr(testLabel, metav1.LabelSelectorOpIn, "foo"),
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				expr(testLabel, metav1.LabelSelectorOpIn, "foo"),
				expr(testLabel, metav1.LabelSelectorOpNotIn, "bar"),
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.expected, selectorsEqual(tc.existing, tc.configured))
			require.Equal(t, tc.expected, selectorsEqual(tc.configured, tc.existing))
		})
	}

	// The normalization must not change the compared selectors.
	selector := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		expr("b", metav1.LabelSelectorOpIn, "y", "x"), expr("a", metav1.LabelSelectorOpExists),
	}}
	before := selector.DeepCopy()
	selectorsEqual(selector, nil)
	require.Equal(t, before, selector)
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
			// A nil selector selects everything like an empty one, and the
			// API server stores an empty one for nil.
			name: "Nil existing and empty object selector",
			existing: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: nil,
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			expected: false,
		},
		{
			name: "Nil existing and empty namespace selector",
			existing: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: nil,
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: &metav1.LabelSelector{},
			},
			expected: false,
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
		{
			// Only the managed label keys used to be compared, so a changed
			// selector of the webhook options never got rolled out.
			name: "namespace selector match labels changed",
			existing: &admissionregv1.MutatingWebhook{
				Name: "foo",
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"team": "a"},
				},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name: "foo",
				NamespaceSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"team": "b"},
				},
			},
			expected: true,
		},
		{
			name: "namespace selector expression of another key changed",
			existing: &admissionregv1.MutatingWebhook{
				Name: "foo",
				NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"a"}},
				}},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name: "foo",
				NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"b"}},
				}},
			},
			expected: true,
		},
		{
			name: "object selector match labels changed",
			existing: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "c"}},
			},
			expected: true,
		},
		{
			name: "reinvocation policy changed",
			existing: &admissionregv1.MutatingWebhook{
				Name:               "foo",
				ReinvocationPolicy: new(admissionregv1.NeverReinvocationPolicy),
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:               "foo",
				ReinvocationPolicy: new(admissionregv1.IfNeededReinvocationPolicy),
			},
			expected: true,
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
			requireUpdate := mutatingWebhookNeedsUpdate(
				logr.Discard(),
				existing,
				&w.config.Webhooks[0],
			)
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

// TestRecordingWebhookSelectors asserts that the daemon gets the selectors
// the recording webhook is configured with.
func TestRecordingWebhookSelectors(t *testing.T) {
	t.Parallel()

	namespaceSelector, objectSelector := RecordingWebhookSelectors(nil, false)
	require.Equal(t, requireLabel(EnableRecordingLabel), namespaceSelector)
	require.Equal(t, &excludeOperatorPods, objectSelector)
	require.NotSame(t, &excludeOperatorPods, objectSelector)

	userSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}
	userObjectSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}}
	opts := []spodapi.WebhookOptions{
		{Name: binding.name, NamespaceSelector: &metav1.LabelSelector{}},
		{
			Name:              RecordingWebhookName,
			NamespaceSelector: userSelector,
			ObjectSelector:    userObjectSelector,
		},
	}

	namespaceSelector, objectSelector = RecordingWebhookSelectors(opts, false)
	require.Equal(t, userSelector, namespaceSelector)
	require.NotSame(t, userSelector, namespaceSelector)
	require.Equal(t, userObjectSelector, objectSelector)

	// They are the ones of the webhook which the operator deploys.
	webhook := GetWebhook(
		logr.Discard(),
		"ns",
		opts,
		"image",
		corev1.PullAlways,
		CAInjectTypeCertManager,
		nil,
		nil,
		false,
	)
	require.Equal(t, webhook.RecordingNamespaceSelector(), namespaceSelector)
	require.Equal(t, webhook.config.Webhooks[recording.index].ObjectSelector, objectSelector)

	// The operator does not apply the options to a static configuration.
	namespaceSelector, objectSelector = RecordingWebhookSelectors(opts, true)
	require.Equal(t, requireLabel(EnableRecordingLabel), namespaceSelector)
	require.Equal(t, &excludeOperatorPods, objectSelector)
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
	assert.False(
		t,
		mutatingWebhookNeedsUpdate(logr.Discard(), existing, &w.config.Webhooks[binding.index]),
	)

	existing.TimeoutSeconds = new(int32(30))
	assert.True(
		t,
		mutatingWebhookNeedsUpdate(logr.Discard(), existing, &w.config.Webhooks[binding.index]),
	)

	existing = configured.Webhooks[binding.index].DeepCopy()
	existing.Rules = existing.Rules[:1]
	assert.True(
		t,
		mutatingWebhookNeedsUpdate(logr.Discard(), existing, &w.config.Webhooks[binding.index]),
	)
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
	assert.True(
		t,
		mutatingWebhookNeedsUpdate(logr.Discard(), existing, &w.config.Webhooks[binding.index]),
	)
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
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: MutatingWebhookConfigName}, mutating))

	for i := range mutating.Webhooks {
		mutating.Webhooks[i].ClientConfig.CABundle = injected
	}

	require.NoError(t, c.Update(ctx, mutating))

	validating := &admissionregv1.ValidatingWebhookConfiguration{}
	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: ValidatingWebhookConfigName}, validating))
	validating.Webhooks[0].ClientConfig.CABundle = injected
	require.NoError(t, c.Update(ctx, validating))

	// Both an update and a create of existing configurations keep the bundle.
	require.NoError(t, newTestWebhook(t, nil).Update(ctx, c))
	require.NoError(t, newTestWebhook(t, nil).Create(ctx, c))

	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: MutatingWebhookConfigName}, mutating))

	for i := range mutating.Webhooks {
		assert.Equal(t, injected, mutating.Webhooks[i].ClientConfig.CABundle)
	}

	require.NoError(t, c.Get(ctx, client.ObjectKey{Name: ValidatingWebhookConfigName}, validating))
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

// aksInjectedExpressions are the match expressions which the AKS admissions
// enforcer adds to the namespace selectors of the webhook configurations.
var aksInjectedExpressions = []metav1.LabelSelectorRequirement{
	{Key: "control-plane", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"true"}},
	{
		Key:      "kubernetes.azure.com/managedby",
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{"aks"},
	},
}

func TestSelectorsEqualIgnoresPlatformInjectedExpressions(t *testing.T) {
	t.Parallel()

	base := func() *metav1.LabelSelector {
		return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: EnableBindingLabel, Operator: metav1.LabelSelectorOpExists},
		}}
	}
	injected := func(s *metav1.LabelSelector) *metav1.LabelSelector {
		if s == nil {
			s = &metav1.LabelSelector{}
		}

		s.MatchExpressions = append(s.MatchExpressions, aksInjectedExpressions...)

		return s
	}

	for _, tc := range []struct {
		name                 string
		existing, configured *metav1.LabelSelector
		expected             bool
	}{
		{name: "injected only", existing: injected(base()), configured: base(), expected: true},
		{name: "injected into nil selector", existing: injected(nil), expected: true},
		{
			name:     "injected and match labels added",
			existing: injected(base()),
			configured: func() *metav1.LabelSelector {
				s := base()
				s.MatchLabels = map[string]string{"team": "a"}

				return s
			}(),
		},
		{
			name: "injected and expression removed",
			existing: injected(func() *metav1.LabelSelector {
				s := base()
				s.MatchExpressions = append(s.MatchExpressions, metav1.LabelSelectorRequirement{
					Key: "team", Operator: metav1.LabelSelectorOpExists,
				})

				return s
			}()),
			configured: base(),
		},
		{
			// A configured expression for an injected key is compared.
			name: "configured expression for an injected key",
			existing: injected(func() *metav1.LabelSelector {
				s := base()
				s.MatchExpressions = append(s.MatchExpressions, metav1.LabelSelectorRequirement{
					Key: "control-plane", Operator: metav1.LabelSelectorOpDoesNotExist,
				})

				return s
			}()),
			configured: func() *metav1.LabelSelector {
				s := base()
				s.MatchExpressions = append(s.MatchExpressions, metav1.LabelSelectorRequirement{
					Key: "control-plane", Operator: metav1.LabelSelectorOpDoesNotExist,
				})

				return s
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			before := tc.existing.DeepCopy()
			require.Equal(t, tc.expected, selectorsEqual(tc.existing, tc.configured))
			require.Equal(t, before, tc.existing, "the existing selector must not change")
		})
	}
}

// injectAKSExpressions adds the AKS expressions to the namespace selectors of
// the stored mutating webhook configuration, like the AKS admissions enforcer
// does on every write.
func injectAKSExpressions(t *testing.T, c client.Client) {
	t.Helper()

	cfg := &admissionregv1.MutatingWebhookConfiguration{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKey{Name: MutatingWebhookConfigName}, cfg))

	for i := range cfg.Webhooks {
		hook := &cfg.Webhooks[i]
		if hook.NamespaceSelector == nil {
			hook.NamespaceSelector = &metav1.LabelSelector{}
		}

		for _, expr := range aksInjectedExpressions {
			if !slices.ContainsFunc(hook.NamespaceSelector.MatchExpressions,
				func(e metav1.LabelSelectorRequirement) bool { return e.Key == expr.Key },
			) {
				hook.NamespaceSelector.MatchExpressions = append(
					hook.NamespaceSelector.MatchExpressions,
					expr,
				)
			}
		}
	}

	require.NoError(t, c.Update(t.Context(), cfg))
}

// reconcileAKSWebhook updates the webhook if needed, lets AKS inject its
// expressions and returns true if the webhook got updated.
func reconcileAKSWebhook(t *testing.T, c client.Client, w *Webhook) bool {
	t.Helper()

	needsUpdate, err := w.NeedsUpdate(t.Context(), c)
	require.NoError(t, err)

	if needsUpdate {
		require.NoError(t, w.Update(t.Context(), c))
		injectAKSExpressions(t, c)
	}

	return needsUpdate
}

func TestWebhook_NeedsUpdateOnAKS(t *testing.T) {
	t.Parallel()

	withLabels := []spodapi.WebhookOptions{{
		Name: binding.name,
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"team": "a"},
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: EnableBindingLabel, Operator: metav1.LabelSelectorOpExists},
			},
		},
	}}
	withExpression := []spodapi.WebhookOptions{
		{
			Name: binding.name,
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: EnableBindingLabel, Operator: metav1.LabelSelectorOpExists},
					{Key: "team", Operator: metav1.LabelSelectorOpExists},
				},
			},
		},
	}
	withoutExpression := []spodapi.WebhookOptions{
		{
			Name: binding.name,
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: EnableBindingLabel, Operator: metav1.LabelSelectorOpExists},
				},
			},
		},
	}

	for _, tc := range []struct {
		name            string
		created, update []spodapi.WebhookOptions
		expectedUpdate  bool
	}{
		{name: "injected expressions only"},
		{name: "match labels added", update: withLabels, expectedUpdate: true},
		{
			name:           "expression removed",
			created:        withExpression,
			update:         withoutExpression,
			expectedUpdate: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := webhookTestClient(t)
			webhook := func(opts []spodapi.WebhookOptions) *Webhook {
				return GetWebhook(
					logr.Discard(), "spo-ns", opts, "image", corev1.PullAlways,
					CAInjectTypeCertManager, nil, nil, false,
				)
			}

			require.NoError(t, webhook(tc.created).Create(t.Context(), c))
			injectAKSExpressions(t, c)

			// Nothing changed besides the injected expressions.
			require.False(t, reconcileAKSWebhook(t, c, webhook(tc.created)))

			// A user change gets rolled out exactly once, and the injected
			// expressions do not make the webhook look outdated afterwards.
			updates := 0

			for range 3 {
				if reconcileAKSWebhook(t, c, webhook(tc.update)) {
					updates++
				}
			}

			expected := 0

			if tc.expectedUpdate {
				expected = 1
			}

			require.Equal(t, expected, updates)

			cfg := &admissionregv1.MutatingWebhookConfiguration{}
			require.NoError(
				t,
				c.Get(t.Context(), client.ObjectKey{Name: MutatingWebhookConfigName}, cfg),
			)

			require.True(t, selectorsEqual(
				cfg.Webhooks[binding.index].NamespaceSelector,
				webhook(tc.update).config.Webhooks[binding.index].NamespaceSelector,
			))
		})
	}
}

func TestWebhook_DeploymentNeedsUpdateReplicasAndPriority(t *testing.T) {
	t.Parallel()

	configured := newTestWebhook(t, nil).deployment
	require.Equal(t, "system-cluster-critical", configured.Spec.Template.Spec.PriorityClassName)

	found := configured.DeepCopy()
	require.False(t, deploymentNeedsUpdate(configured, found))

	found.Spec.Replicas = new(int32(1))
	require.True(t, deploymentNeedsUpdate(configured, found), "scaled down")

	found = configured.DeepCopy()
	found.Spec.Template.Spec.PriorityClassName = ""
	require.True(t, deploymentNeedsUpdate(configured, found), "priority class of an older release")
}

// The fields which the API server defaults are compared with their defaults,
// and the client configuration, the admission review versions and the match
// policy are compared, too.
func TestDifferingHookField(t *testing.T) {
	t.Parallel()

	configured := getWebhookConfig(false, "ns").Webhooks[binding.index]

	for name, tc := range map[string]struct {
		mutate func(*admissionregv1.MutatingWebhook)
		want   string
	}{
		"equal": {mutate: func(*admissionregv1.MutatingWebhook) {}},
		"defaulted match policy": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.MatchPolicy = new(admissionregv1.Equivalent) },
		},
		"defaulted service port": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.ClientConfig.Service.Port = new(int32(443)) },
		},
		"injected CA bundle": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.ClientConfig.CABundle = []byte("ca") },
		},
		"match policy": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.MatchPolicy = new(admissionregv1.Exact) },
			want:   "matchPolicy",
		},
		"service port": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.ClientConfig.Service.Port = new(int32(8443)) },
			want:   "clientConfig",
		},
		"service namespace": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.ClientConfig.Service.Namespace = "other" },
			want:   "clientConfig",
		},
		"service path": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.ClientConfig.Service.Path = new("/other") },
			want:   "clientConfig",
		},
		"admission review versions": {
			mutate: func(h *admissionregv1.MutatingWebhook) {
				h.AdmissionReviewVersions = []string{"v1", "v1beta1"}
			},
			want: "admissionReviewVersions",
		},
		"failure policy": {
			mutate: func(h *admissionregv1.MutatingWebhook) { h.FailurePolicy = new(admissionregv1.Ignore) },
			want:   "failurePolicy",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			existing := configured.DeepCopy()
			tc.mutate(existing)
			assert.Equal(t, tc.want,
				differingHookField(mutatingHookFields(existing), mutatingHookFields(&configured)))
		})
	}
}

// The validating webhooks are matched by name, not by position.
func TestWebhook_ValidatingConfigNeedsUpdate(t *testing.T) {
	t.Parallel()

	w := newTestWebhook(t, nil)
	existing := w.validatingConfig.DeepCopy()

	c := webhookTestClient(t, existing)
	update, err := w.validatingConfigNeedsUpdate(t.Context(), c)
	require.NoError(t, err)
	require.False(t, update)

	existing.Webhooks[0].Name = "other.spo.io"
	c = webhookTestClient(t, existing)
	update, err = w.validatingConfigNeedsUpdate(t.Context(), c)
	require.NoError(t, err)
	require.True(t, update)
}

func TestApplyWebhookOptionsCopiesSelectors(t *testing.T) {
	t.Parallel()

	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}
	opts := []spodapi.WebhookOptions{{
		Name:           binding.name,
		ObjectSelector: selector,
		FailurePolicy:  new(admissionregv1.Ignore),
	}}

	cfg := getWebhookConfig(false, "ns")
	applyWebhookOptions(cfg, opts, "ns")

	// Changing the applied configuration must not change the SPOD.
	cfg.Webhooks[binding.index].ObjectSelector.MatchLabels["a"] = "changed"
	*cfg.Webhooks[binding.index].FailurePolicy = admissionregv1.Fail

	require.Equal(t, "b", selector.MatchLabels["a"])
	require.Equal(t, admissionregv1.Ignore, *opts[0].FailurePolicy)
}

func TestWebhook_BindingWarnings(t *testing.T) {
	t.Parallel()

	newWebhook := func(opts ...spodapi.WebhookOptions) *Webhook {
		return GetWebhook(
			logr.Discard(), "spo-ns", opts, "image", corev1.PullAlways,
			CAInjectTypeCertManager, nil, nil, false,
		)
	}

	require.Empty(t, newWebhook().BindingWarnings())

	// Options of other webhooks and a stricter policy are fine.
	require.Empty(t, newWebhook(
		spodapi.WebhookOptions{Name: recording.name, FailurePolicy: new(admissionregv1.Ignore)},
		spodapi.WebhookOptions{Name: binding.name, FailurePolicy: new(admissionregv1.Fail)},
	).BindingWarnings())

	warnings := newWebhook(spodapi.WebhookOptions{
		Name:           binding.name,
		FailurePolicy:  new(admissionregv1.Ignore),
		ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
	}).BindingWarnings()
	require.Len(t, warnings, 2)
	require.Contains(t, warnings[0], "failurePolicy Ignore")
	require.Contains(t, warnings[1], "objectSelector")
}

// The webhook is critical for the cluster, unless the daemon pods use another
// priority class than their default, which then applies to the webhook too.
func TestWebhook_UseDaemonPriorityClass(t *testing.T) {
	t.Parallel()

	for daemonClass, want := range map[string]string{
		DefaultPriorityClassName: "system-cluster-critical",
		"custom":                 "custom",
		"":                       "",
	} {
		w := newTestWebhook(t, nil)
		w.UseDaemonPriorityClass(daemonClass)
		require.Equal(t, want, w.deployment.Spec.Template.Spec.PriorityClassName, daemonClass)
	}
}
