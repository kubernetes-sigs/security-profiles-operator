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
	"fmt"
	"iter"
	"reflect"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	replicas    int32 = 3
	defaultMode int32 = 420
	// timeoutSeconds bounds how long a request waits for a webhook. The
	// handlers only read from the informer cache, so they either answer quickly
	// or not at all, and a hanging webhook must not stall pod admission for
	// long.
	timeoutSeconds          int32 = 10
	allScopes                     = admissionregv1.AllScopes
	failurePolicyFail             = admissionregv1.Fail
	failurePolicyIgnore           = admissionregv1.Ignore
	reinvocationPolicy            = admissionregv1.IfNeededReinvocationPolicy
	caBundle                      = []byte("Cg==")
	sideEffects                   = admissionregv1.SideEffectClassNone
	sideEffectsNoneOnDryRun       = admissionregv1.SideEffectClassNoneOnDryRun
	admissionReviewVersions       = []string{"v1"}
	// The scope of the rules is set to its default explicitly, so that the
	// configured rules compare equal to the ones returned by the API server.
	bindingRules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				"CREATE",
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
				Scope:       &allScopes,
			},
		},
		{
			// Ephemeral containers are added to running pods, so they have to
			// be bound as well to not escape the enforced profiles.
			Operations: []admissionregv1.OperationType{
				"UPDATE",
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods/ephemeralcontainers"},
				Scope:       &allScopes,
			},
		},
	}
	recordingRules = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				"CREATE", "UPDATE",
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
				Scope:       &allScopes,
			},
		},
	}
	rulesExec = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				"*",
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods/exec", "pods/ephemeralcontainers"},
				Scope:       &allScopes,
			},
		},
	}
	rulesNodeDebuggingPod = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				"CREATE",
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
				Scope:       &allScopes,
			},
		},
	}
	objectSelectorNodeDebuggingPod = metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app.kubernetes.io/managed-by": "kubectl-debug",
		},
	}

	// excludeOperatorPods keeps a webhook off the operator's own pods, which
	// must not depend on the webhook being up to start. It matches a pod label,
	// so a pod author can claim it to opt out.
	excludeOperatorPods = metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      labelName,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{config.OperatorName, webhookName},
			},
		},
	}
)

// systemNamespaces are the namespaces of the cluster components. Execs into
// their pods do not get the exec metadata injected, because the injected
// command requires an env binary in the container image, which minimal system
// images often do not ship.
var systemNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
	corev1.NamespaceNodeLease,
}

// excludeSystemNamespaces selects all namespaces except the system ones and
// the operator namespace. Namespaces cannot be matched by prefix, so for
// example OpenShift namespaces have to be excluded through the webhook
// options of the SPOD, which replace this selector.
func excludeSystemNamespaces(operatorNamespace string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   append(slices.Clone(systemNamespaces), operatorNamespace),
			},
		},
	}
}

// requireLabel selects namespaces carrying the webhook's enable label.
func requireLabel(requiredLabel string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      requiredLabel,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	}
}

// excludeOperatorNamespace additionally keeps a webhook out of the operator's
// own namespace. Unlike excludeOperatorPods this cannot be opted out of by the
// pod author, because "kubernetes.io/metadata.name" is set by the API server.
//
// It is used for binding and not for recording, and the asymmetry is
// deliberate. Escaping the binding webhook means running without the profile a
// ProfileBinding enforces, so that exclusion has to be unforgeable, and nothing
// binds profiles to workloads in the operator's own namespace. Escaping the
// recording webhook only means not being recorded, which is no one's security
// boundary, and recording a workload that runs in the operator namespace is a
// supported thing to do: the CI base profile recording does exactly that.
//
// The namespace is the one the controller itself is running in, passed down
// from GetWebhook, rather than read from the environment here: guessing the
// default install namespace would silently stop excluding the operator on any
// install that uses a different namespace.
func excludeOperatorNamespace(requiredLabel, operatorNamespace string) *metav1.LabelSelector {
	return withOperatorNamespaceExcluded(requireLabel(requiredLabel), operatorNamespace)
}

// withOperatorNamespaceExcluded appends the operator namespace exclusion to
// selector, unless it is already there, and returns it.
func withOperatorNamespaceExcluded(
	selector *metav1.LabelSelector, operatorNamespace string,
) *metav1.LabelSelector {
	exclusion := metav1.LabelSelectorRequirement{
		Key:      corev1.LabelMetadataName,
		Operator: metav1.LabelSelectorOpNotIn,
		Values:   []string{operatorNamespace},
	}

	excluded := slices.ContainsFunc(
		selector.MatchExpressions,
		func(r metav1.LabelSelectorRequirement) bool { return reflect.DeepEqual(r, exclusion) },
	)
	if !excluded {
		selector.MatchExpressions = append(selector.MatchExpressions, exclusion)
	}

	return selector
}

const (
	// EnableRecordingLabel this label can be applied to a namespace or a pod
	// in order to enable profile recording.
	EnableRecordingLabel = "spo.x-k8s.io/enable-recording"
	// EnableBindingLabel this label can be applied to a namespace in order to
	// enable profile binding.
	EnableBindingLabel = "spo.x-k8s.io/enable-binding"
)

const (
	// MutatingWebhookConfigName is the name of the mutating webhook
	// configuration of the operator.
	MutatingWebhookConfigName = "spo-mutating-webhook-configuration"
	// ValidatingWebhookConfigName is the name of the validating webhook
	// configuration of the operator.
	ValidatingWebhookConfigName = "spo-validating-webhook-configuration"

	// WebhookName is the name of the deployment and the pod disruption
	// budget of the managed webhook.
	WebhookName = webhookName
	// WebhookServiceName is the name of the service of the managed webhook.
	WebhookServiceName = serviceName
	// RecordingWebhookName is the name of the recording webhook in the
	// mutating webhook configuration.
	RecordingWebhookName = "recording.spo.io"

	// openshiftRequiredSCCAnnotation pins the SCC which OpenShift admits a pod
	// with, instead of choosing one of the SCCs the pod is allowed to use.
	openshiftRequiredSCCAnnotation = "openshift.io/required-scc"

	webhookName                  = config.OperatorName + "-webhook"
	webhookPriorityClassName     = "system-cluster-critical"
	serviceAccountName           = "spo-webhook"
	certsMountPath               = "/tmp/k8s-webhook-server/serving-certs"
	serviceName                  = "webhook-service"
	webhookServerCert            = "webhook-server-cert"
	rawSelinuxProfileValidation  = "rawselinuxprofile-validation.spo.io"
	rawSelinuxProfileWebhookPath = "/validate-rawselinuxprofile"
	certManagerInjectAnnotation  = "cert-manager.io/inject-ca-from"
)

type webhook struct {
	index int
	name  string
	path  string
}

var (
	binding                  = webhook{0, "binding.spo.io", "/mutate-v1-pod-binding"}
	recording                = webhook{1, RecordingWebhookName, "/mutate-v1-pod-recording"}
	execMetadata             = webhook{2, "execmetadata.spo.io", "/mutate-v1-exec-metadata"}
	nodeDebuggingPodMetadata = webhook{3, "nodedebuggingpod.spo.io", "/mutate-v1-exec-metadata"}
)

type Webhook struct {
	log              logr.Logger
	deployment       *appsv1.Deployment
	config           *admissionregv1.MutatingWebhookConfiguration
	validatingConfig *admissionregv1.ValidatingWebhookConfiguration
	service          *corev1.Service
	pdb              *policyv1.PodDisruptionBudget
}

func GetWebhook(
	log logr.Logger,
	namespace string,
	webhookOpts []spodapi.WebhookOptions,
	image string,
	pullPolicy corev1.PullPolicy,
	caInjectType CAInjectType,
	tolerations []corev1.Toleration,
	imagePullSecrets []corev1.LocalObjectReference,
	execMetadataWebhookEnabled bool,
) *Webhook {
	deployment := webhookDeployment.DeepCopy()
	deployment.Namespace = namespace

	if len(tolerations) > 0 {
		deployment.Spec.Template.Spec.Tolerations = tolerations
	}

	if len(imagePullSecrets) > 0 {
		deployment.Spec.Template.Spec.ImagePullSecrets = imagePullSecrets
	}

	ctr := &deployment.Spec.Template.Spec.Containers[0]
	ctr.Image = image
	ctr.ImagePullPolicy = pullPolicy

	cfg := getWebhookConfig(execMetadataWebhookEnabled, namespace).DeepCopy()
	cfg.Webhooks[binding.index].ClientConfig.Service.Namespace = namespace
	cfg.Webhooks[recording.index].ClientConfig.Service.Namespace = namespace

	if execMetadataWebhookEnabled {
		cfg.Webhooks[execMetadata.index].ClientConfig.Service.Namespace = namespace
		cfg.Webhooks[nodeDebuggingPodMetadata.index].ClientConfig.Service.Namespace = namespace
	}

	service := webhookService.DeepCopy()
	service.Namespace = namespace

	pdb := webhookPDB.DeepCopy()
	pdb.Namespace = namespace

	// cert-manager looks up the certificate in the namespace the operator
	// created it in, see GetCertManagerResources.
	certManagerCA := namespace + "/" + webhookCert.Name

	switch caInjectType {
	case CAInjectTypeCertManager:
		cfg.Annotations = map[string]string{
			certManagerInjectAnnotation: certManagerCA,
		}
	case CAInjectTypeOpenShift:
		// if there's any OCP specific webhook opts, apply them here
		cfg.Annotations = map[string]string{
			"service.beta.openshift.io/inject-cabundle": "true",
		}
		service.Annotations = map[string]string{
			openshiftCertAnnotation: webhookServerCert,
		}
	}

	// then apply the user-specified opts
	applyWebhookOptions(cfg, webhookOpts, namespace)

	valCfg := getValidatingWebhookConfig().DeepCopy()
	valCfg.Webhooks[0].ClientConfig.Service.Namespace = namespace

	switch caInjectType {
	case CAInjectTypeCertManager:
		valCfg.Annotations = map[string]string{
			certManagerInjectAnnotation: certManagerCA,
		}
	case CAInjectTypeOpenShift:
		valCfg.Annotations = map[string]string{
			"service.beta.openshift.io/inject-cabundle": "true",
		}
	}

	return &Webhook{
		log:              log,
		deployment:       deployment,
		config:           cfg,
		validatingConfig: valCfg,
		service:          service,
		pdb:              pdb,
	}
}

// UseDaemonPriorityClass sets the priority class of the webhook pods for the
// priority class of the daemon pods. The webhook keeps system-cluster-critical
// while the daemon uses its default priority class. Any other daemon priority
// class, like the one a cluster which restricts the critical priority classes
// needs, applies to the webhook as well.
func (w *Webhook) UseDaemonPriorityClass(daemonPriorityClassName string) {
	if daemonPriorityClassName != DefaultPriorityClassName {
		w.deployment.Spec.Template.Spec.PriorityClassName = daemonPriorityClassName
	}
}

// RecordingNamespaceSelector returns the namespace selector of the recording
// webhook, which selects all namespaces if nil.
func (w *Webhook) RecordingNamespaceSelector() *metav1.LabelSelector {
	return w.config.Webhooks[recording.index].NamespaceSelector
}

// RecordingWebhookSelectors returns the namespace and the object selector of
// the recording webhook as the operator deploys it, with the webhook options of
// the SPOD applied unless the webhook configuration is static, which the
// operator leaves alone. A nil selector selects everything. The pod author
// controls the recording annotations of the pods the webhook does not apply
// to, so the daemon checks the selectors as well.
func RecordingWebhookSelectors(
	opts []spodapi.WebhookOptions, static bool,
) (namespaceSelector, objectSelector *metav1.LabelSelector) {
	cfg := getWebhookConfig(false, "").DeepCopy()
	if !static {
		applyWebhookOptions(cfg, opts, "")
	}

	hook := &cfg.Webhooks[recording.index]

	return hook.NamespaceSelector, hook.ObjectSelector
}

func (w *Webhook) Create(ctx context.Context, c client.Client) error {
	for k, o := range w.objects() {
		if err := c.Create(ctx, o); err != nil {
			if errors.IsAlreadyExists(err) {
				if k == "config" || k == "validatingConfig" {
					if err := w.update(ctx, c, o); err != nil {
						return fmt.Errorf("updating %s: %w", k, err)
					}
				}

				continue
			}

			return fmt.Errorf("creating %s: %w", k, err)
		}
	}

	return nil
}

func applyWebhookOptions(
	cfg *admissionregv1.MutatingWebhookConfiguration,
	opts []spodapi.WebhookOptions,
	operatorNamespace string,
) {
	for i := range cfg.Webhooks {
		hook := &cfg.Webhooks[i]

		for j := range opts {
			userOpt := &opts[j]
			if userOpt.Name != hook.Name {
				continue
			}

			if userOpt.FailurePolicy != nil {
				hook.FailurePolicy = new(*userOpt.FailurePolicy)
			}

			if userOpt.NamespaceSelector != nil {
				hook.NamespaceSelector = userOpt.NamespaceSelector.DeepCopy()

				// A custom selector narrows or widens which namespaces opt in,
				// but must not lift the operator namespace exclusion that
				// makes binding a security boundary.
				if hook.Name == binding.name {
					withOperatorNamespaceExcluded(hook.NamespaceSelector, operatorNamespace)
				}
			}

			if userOpt.ObjectSelector != nil {
				hook.ObjectSelector = userOpt.ObjectSelector.DeepCopy()
			}
		}
	}
}

// BindingWarnings returns why the webhook options of the SPOD weaken the
// enforcement of the profile bindings, if they do. The options are valid and
// get applied, but an administrator should know what they mean.
func (w *Webhook) BindingWarnings() []string {
	var warnings []string

	for i := range w.config.Webhooks {
		hook := &w.config.Webhooks[i]
		if hook.Name != binding.name {
			continue
		}

		if ptr.Deref(hook.FailurePolicy, admissionregv1.Fail) == admissionregv1.Ignore {
			warnings = append(warnings, fmt.Sprintf(
				"the failurePolicy Ignore of the %s webhook admits pods without their bound "+
					"profiles while the webhook is unavailable", binding.name,
			))
		}

		if hook.ObjectSelector != nil &&
			(len(hook.ObjectSelector.MatchLabels) > 0 || len(hook.ObjectSelector.MatchExpressions) > 0) {
			warnings = append(warnings, fmt.Sprintf(
				"the objectSelector of the %s webhook exempts the pods it does not select "+
					"from the profile bindings", binding.name,
			))
		}
	}

	return warnings
}

// NeedsUpdate returns true if any of the webhook objects is missing or
// differs from the configured one.
func (w *Webhook) NeedsUpdate(ctx context.Context, c client.Client) (bool, error) {
	for _, needsUpdate := range []func(context.Context, client.Client) (bool, error){
		w.mutatingConfigNeedsUpdate,
		w.validatingConfigNeedsUpdate,
		w.workloadNeedsUpdate,
	} {
		if update, err := needsUpdate(ctx, c); err != nil || update {
			return update, err
		}
	}

	return false, nil
}

// mutatingConfigNeedsUpdate returns true if the mutating webhook configuration
// is missing or differs from the configured one.
func (w *Webhook) mutatingConfigNeedsUpdate(ctx context.Context, c client.Client) (bool, error) {
	existing := &admissionregv1.MutatingWebhookConfiguration{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(w.config), existing); err != nil {
		if errors.IsNotFound(err) {
			w.log.V(1).Info("creating missing webhook configuration")

			return true, nil
		}

		return false, fmt.Errorf("getting mutating webhook configuration: %w", err)
	}

	if annotationsDiffer(w.config.Annotations, existing.Annotations) ||
		len(existing.Webhooks) != len(w.config.Webhooks) {
		w.log.V(1).Info("updating webhook configuration")

		return true, nil
	}

	for i := range w.config.Webhooks {
		configured := &w.config.Webhooks[i]

		idx := slices.IndexFunc(existing.Webhooks, func(h admissionregv1.MutatingWebhook) bool {
			return h.Name == configured.Name
		})
		if idx < 0 || mutatingWebhookNeedsUpdate(w.log, &existing.Webhooks[idx], configured) {
			w.log.V(1).Info("updating webhook configuration", "name", configured.Name)

			return true, nil
		}
	}

	return false, nil
}

// validatingConfigNeedsUpdate returns true if the validating webhook
// configuration is missing or differs from the configured one.
func (w *Webhook) validatingConfigNeedsUpdate(ctx context.Context, c client.Client) (bool, error) {
	existing := &admissionregv1.ValidatingWebhookConfiguration{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(w.validatingConfig), existing); err != nil {
		if errors.IsNotFound(err) {
			w.log.V(1).Info("creating missing validating webhook configuration")

			return true, nil
		}

		return false, fmt.Errorf("getting validating webhook configuration: %w", err)
	}

	if annotationsDiffer(w.validatingConfig.Annotations, existing.Annotations) ||
		len(existing.Webhooks) != len(w.validatingConfig.Webhooks) {
		w.log.V(1).Info("updating validating webhook configuration")

		return true, nil
	}

	for i := range w.validatingConfig.Webhooks {
		configured := &w.validatingConfig.Webhooks[i]

		idx := slices.IndexFunc(existing.Webhooks, func(h admissionregv1.ValidatingWebhook) bool {
			return h.Name == configured.Name
		})
		if idx < 0 {
			w.log.V(1).Info("updating validating webhook configuration", "name", configured.Name)

			return true, nil
		}

		if field := differingHookField(
			validatingHookFields(&existing.Webhooks[idx]), validatingHookFields(configured),
		); field != "" {
			w.log.V(1).Info("updating validating webhook configuration",
				"name", configured.Name, "field", field)

			return true, nil
		}
	}

	return false, nil
}

// workloadNeedsUpdate returns true if the webhook deployment differs from the
// configured one, or if the service is missing.
func (w *Webhook) workloadNeedsUpdate(ctx context.Context, c client.Client) (bool, error) {
	existingDeployment := &appsv1.Deployment{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(w.deployment), existingDeployment); err != nil {
		if errors.IsNotFound(err) {
			return true, nil
		}

		return false, fmt.Errorf("getting webhook deployment: %w", err)
	}

	if deploymentNeedsUpdate(w.deployment, existingDeployment) {
		w.log.V(1).Info("updating webhook deployment")

		return true, nil
	}

	existingPDB := &policyv1.PodDisruptionBudget{}

	for _, o := range []struct {
		key client.ObjectKey
		obj client.Object
	}{
		{client.ObjectKeyFromObject(w.service), &corev1.Service{}},
		{client.ObjectKeyFromObject(w.pdb), existingPDB},
	} {
		key := o.key
		if err := c.Get(ctx, key, o.obj); err != nil {
			if errors.IsNotFound(err) {
				w.log.V(1).Info("creating missing webhook object", "name", key.Name)

				return true, nil
			}

			return false, fmt.Errorf("getting webhook object %s: %w", key.Name, err)
		}
	}

	if !apiequality.Semantic.DeepEqual(existingPDB.Spec.MinAvailable, w.pdb.Spec.MinAvailable) ||
		!apiequality.Semantic.DeepEqual(existingPDB.Spec.Selector, w.pdb.Spec.Selector) ||
		!apiequality.Semantic.DeepEqual(
			existingPDB.Spec.UnhealthyPodEvictionPolicy, w.pdb.Spec.UnhealthyPodEvictionPolicy,
		) {
		w.log.V(1).Info("updating webhook pod disruption budget")

		return true, nil
	}

	return false, nil
}

// deploymentNeedsUpdate returns true if the found webhook deployment differs
// from the configured one. DeepDerivative ignores the fields which are unset
// in the configured deployment, like the ones defaulted by the API server, so
// the fields which can get cleared are compared explicitly.
func deploymentNeedsUpdate(configured, found *appsv1.Deployment) bool {
	cSpec, fSpec := &configured.Spec.Template.Spec, &found.Spec.Template.Spec

	if !ptr.Equal(configured.Spec.Replicas, found.Spec.Replicas) ||
		cSpec.PriorityClassName != fSpec.PriorityClassName ||
		len(cSpec.Containers) != len(fSpec.Containers) ||
		len(cSpec.Volumes) != len(fSpec.Volumes) {
		return true
	}

	for i := range cSpec.Containers {
		if len(cSpec.Containers[i].Args) != len(fSpec.Containers[i].Args) ||
			len(cSpec.Containers[i].Env) != len(fSpec.Containers[i].Env) ||
			len(cSpec.Containers[i].VolumeMounts) != len(fSpec.Containers[i].VolumeMounts) ||
			(cSpec.Containers[i].ReadinessProbe == nil) != (fSpec.Containers[i].ReadinessProbe == nil) {
			return true
		}
	}

	return !apiequality.Semantic.DeepEqual(cSpec.Tolerations, fSpec.Tolerations) ||
		!apiequality.Semantic.DeepEqual(cSpec.ImagePullSecrets, fSpec.ImagePullSecrets) ||
		!apiequality.Semantic.DeepEqual(cSpec.Affinity, fSpec.Affinity) ||
		!apiequality.Semantic.DeepDerivative(configured.Spec.Template, found.Spec.Template)
}

// annotationsDiffer returns true if any of the configured annotations is
// missing or different in the existing ones.
func annotationsDiffer(configured, existing map[string]string) bool {
	for k, v := range configured {
		if existing[k] != v {
			return true
		}
	}

	return false
}

// hookFields are the fields which mutating and validating webhooks share.
type hookFields struct {
	clientConfig            *admissionregv1.WebhookClientConfig
	rules                   []admissionregv1.RuleWithOperations
	failurePolicy           *admissionregv1.FailurePolicyType
	matchPolicy             *admissionregv1.MatchPolicyType
	namespaceSelector       *metav1.LabelSelector
	objectSelector          *metav1.LabelSelector
	sideEffects             *admissionregv1.SideEffectClass
	timeoutSeconds          *int32
	admissionReviewVersions []string
}

func mutatingHookFields(h *admissionregv1.MutatingWebhook) *hookFields {
	return &hookFields{
		clientConfig:            &h.ClientConfig,
		rules:                   h.Rules,
		failurePolicy:           h.FailurePolicy,
		matchPolicy:             h.MatchPolicy,
		namespaceSelector:       h.NamespaceSelector,
		objectSelector:          h.ObjectSelector,
		sideEffects:             h.SideEffects,
		timeoutSeconds:          h.TimeoutSeconds,
		admissionReviewVersions: h.AdmissionReviewVersions,
	}
}

func validatingHookFields(h *admissionregv1.ValidatingWebhook) *hookFields {
	return &hookFields{
		clientConfig:            &h.ClientConfig,
		rules:                   h.Rules,
		failurePolicy:           h.FailurePolicy,
		matchPolicy:             h.MatchPolicy,
		namespaceSelector:       h.NamespaceSelector,
		objectSelector:          h.ObjectSelector,
		sideEffects:             h.SideEffects,
		timeoutSeconds:          h.TimeoutSeconds,
		admissionReviewVersions: h.AdmissionReviewVersions,
	}
}

// The API server defaults these fields if they are unset.
const (
	defaultMatchPolicy = admissionregv1.Equivalent
	defaultServicePort = int32(443)
)

// differingHookField returns the name of the first field which differs
// between the existing and the configured webhook, or an empty string. The CA
// bundle is not compared, because it gets injected.
func differingHookField(existing, configured *hookFields) string {
	switch {
	case !ptr.Equal(existing.timeoutSeconds, configured.timeoutSeconds):
		return "timeoutSeconds"
	case !ptr.Equal(existing.sideEffects, configured.sideEffects):
		return "sideEffects"
	case !reflect.DeepEqual(existing.rules, configured.rules):
		return "rules"
	case !ptr.Equal(existing.failurePolicy, configured.failurePolicy):
		return "failurePolicy"
	case ptr.Deref(existing.matchPolicy, defaultMatchPolicy) !=
		ptr.Deref(configured.matchPolicy, defaultMatchPolicy):
		return "matchPolicy"
	case !ptr.Equal(existing.clientConfig.URL, configured.clientConfig.URL) ||
		!serviceReferencesEqual(existing.clientConfig.Service, configured.clientConfig.Service):
		return "clientConfig"
	case !slices.Equal(existing.admissionReviewVersions, configured.admissionReviewVersions):
		return "admissionReviewVersions"
	// The selectors are compared as a whole, so that any change to the
	// webhook options of the SPOD gets rolled out. A nil selector matches
	// everything like an empty one, and some platforms store an empty
	// selector for a nil one. Expressions which platforms like AKS inject
	// are ignored, see platformInjectedSelectorKeys.
	case !selectorsEqual(existing.namespaceSelector, configured.namespaceSelector):
		return "namespaceSelector"
	case !selectorsEqual(existing.objectSelector, configured.objectSelector):
		return "objectSelector"
	default:
		return ""
	}
}

// serviceReferencesEqual returns true if both references point to the same
// path of the same service port.
func serviceReferencesEqual(existing, configured *admissionregv1.ServiceReference) bool {
	if existing == nil || configured == nil {
		return existing == configured
	}

	return existing.Namespace == configured.Namespace &&
		existing.Name == configured.Name &&
		ptr.Equal(existing.Path, configured.Path) &&
		ptr.Deref(
			existing.Port,
			defaultServicePort,
		) == ptr.Deref(
			configured.Port,
			defaultServicePort,
		)
}

// mutatingWebhookNeedsUpdate returns true if the existing mutating webhook
// differs from the configured one.
func mutatingWebhookNeedsUpdate(
	log logr.Logger, existing, configured *admissionregv1.MutatingWebhook,
) bool {
	field := differingHookField(mutatingHookFields(existing), mutatingHookFields(configured))
	if field == "" && !ptr.Equal(existing.ReinvocationPolicy, configured.ReinvocationPolicy) {
		field = "reinvocationPolicy"
	}

	if field == "" {
		return false
	}

	log.V(1).Info("updating webhook", "name", configured.Name, "field", field)

	return true
}

// platformInjectedSelectorKeys are the label keys of match expressions which
// platforms inject into the selectors of every webhook configuration. The AKS
// admissions enforcer adds NotIn expressions for these keys, so that webhooks
// skip the system namespaces of the cluster. Comparing them would report every
// reconciliation as a change, keep rewriting the configuration and leave the
// SPOD stuck in the updating state.
var platformInjectedSelectorKeys = []string{
	"control-plane",
	"kubernetes.azure.com/managedby",
}

// selectorsEqual returns true if both label selectors select the same
// objects. A nil selector equals an empty one, and the order of the match
// expressions and their values does not matter. Match expressions of the
// existing selector which a platform injected get ignored, as long as the
// configured selector has no expression for their key.
func selectorsEqual(existing, configured *metav1.LabelSelector) bool {
	return apiequality.Semantic.DeepEqual(
		normalizeSelector(withoutInjectedExpressions(existing, configured)),
		normalizeSelector(configured),
	)
}

// withoutInjectedExpressions returns the existing selector without the match
// expressions for the platformInjectedSelectorKeys which do not occur in the
// configured selector. It returns the existing selector unchanged if there are
// none.
func withoutInjectedExpressions(existing, configured *metav1.LabelSelector) *metav1.LabelSelector {
	if existing == nil {
		return nil
	}

	injected := func(req metav1.LabelSelectorRequirement) bool {
		if !slices.Contains(platformInjectedSelectorKeys, req.Key) {
			return false
		}

		return configured == nil || !slices.ContainsFunc(configured.MatchExpressions,
			func(c metav1.LabelSelectorRequirement) bool { return c.Key == req.Key },
		)
	}

	if !slices.ContainsFunc(existing.MatchExpressions, injected) {
		return existing
	}

	res := existing.DeepCopy()
	res.MatchExpressions = slices.DeleteFunc(res.MatchExpressions, injected)

	return res
}

// normalizeSelector returns a copy of the selector with nil mapped to an
// empty selector and the match expressions and their values sorted.
func normalizeSelector(selector *metav1.LabelSelector) *metav1.LabelSelector {
	if selector == nil {
		return &metav1.LabelSelector{}
	}

	res := selector.DeepCopy()
	if len(res.MatchLabels) == 0 {
		res.MatchLabels = nil
	}

	if len(res.MatchExpressions) == 0 {
		res.MatchExpressions = nil
	}

	for i := range res.MatchExpressions {
		slices.Sort(res.MatchExpressions[i].Values)

		if len(res.MatchExpressions[i].Values) == 0 {
			res.MatchExpressions[i].Values = nil
		}
	}

	slices.SortFunc(res.MatchExpressions, func(a, b metav1.LabelSelectorRequirement) int {
		return strings.Compare(
			fmt.Sprint(a.Key, a.Operator, a.Values),
			fmt.Sprint(b.Key, b.Operator, b.Values),
		)
	})

	return res
}

// Update updates the webhook objects, and creates the ones which are missing.
func (w *Webhook) Update(ctx context.Context, c client.Client) error {
	for k, o := range w.objects() {
		if err := w.update(ctx, c, o); err != nil {
			return fmt.Errorf("updating %s: %w", k, err)
		}
	}

	return nil
}

// update writes the configured object and creates it if it does not exist.
func (w *Webhook) update(ctx context.Context, c client.Client, obj client.Object) error {
	if deployment, ok := obj.(*appsv1.Deployment); ok {
		return updateDeployment(ctx, c, deployment)
	}

	if err := keepCABundles(ctx, c, obj); err != nil {
		return err
	}

	err := c.Patch(ctx, obj, client.Merge)
	if errors.IsNotFound(err) {
		err = c.Create(ctx, obj)
	}

	return err
}

// updateDeployment replaces the spec of the webhook deployment. A JSON merge
// patch would keep fields which got cleared in the configuration, like the
// tolerations or the image pull secrets.
func updateDeployment(ctx context.Context, c client.Client, configured *appsv1.Deployment) error {
	found := &appsv1.Deployment{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(configured), found); err != nil {
		if errors.IsNotFound(err) {
			return c.Create(ctx, configured)
		}

		return fmt.Errorf("getting deployment: %w", err)
	}

	updated := found.DeepCopy()
	updated.Spec = *configured.Spec.DeepCopy()

	return c.Update(ctx, updated)
}

// keepCABundles copies the CA bundles which got injected into the existing
// webhook configuration into the configured one. A merge patch replaces the
// whole list of webhooks, so the placeholder bundle would otherwise break the
// webhooks until the CA gets injected again.
func keepCABundles(ctx context.Context, c client.Client, configured client.Object) error {
	var existing client.Object

	switch configured.(type) {
	case *admissionregv1.MutatingWebhookConfiguration:
		existing = &admissionregv1.MutatingWebhookConfiguration{}
	case *admissionregv1.ValidatingWebhookConfiguration:
		existing = &admissionregv1.ValidatingWebhookConfiguration{}
	default:
		return nil
	}

	if err := c.Get(ctx, client.ObjectKeyFromObject(configured), existing); err != nil {
		return client.IgnoreNotFound(err)
	}

	bundles := map[string][]byte{}
	for name, clientConfig := range clientConfigs(existing) {
		bundles[name] = clientConfig.CABundle
	}

	for name, clientConfig := range clientConfigs(configured) {
		if bundle := bundles[name]; len(bundle) > 0 {
			clientConfig.CABundle = bundle
		}
	}

	return nil
}

// clientConfigs returns the client configurations of the webhooks of a
// webhook configuration by webhook name.
func clientConfigs(obj client.Object) map[string]*admissionregv1.WebhookClientConfig {
	res := map[string]*admissionregv1.WebhookClientConfig{}

	switch o := obj.(type) {
	case *admissionregv1.MutatingWebhookConfiguration:
		for i := range o.Webhooks {
			res[o.Webhooks[i].Name] = &o.Webhooks[i].ClientConfig
		}
	case *admissionregv1.ValidatingWebhookConfiguration:
		for i := range o.Webhooks {
			res[o.Webhooks[i].Name] = &o.Webhooks[i].ClientConfig
		}
	}

	return res
}

// objects returns the webhook objects by name. The webhook configurations
// come last, so that the webhook they point to is set up when they apply.
func (w *Webhook) objects() iter.Seq2[string, client.Object] {
	return namedObjects([]namedObject{
		{"service", w.service},
		{"pdb", w.pdb},
		{"deployment", w.deployment},
		{"config", w.config},
		{"validatingConfig", w.validatingConfig},
	})
}

// namedObject is an object with the name used in error messages.
type namedObject struct {
	name string
	obj  client.Object
}

// namedObjects returns the objects in their order.
func namedObjects(objects []namedObject) iter.Seq2[string, client.Object] {
	return func(yield func(string, client.Object) bool) {
		for _, o := range objects {
			if !yield(o.name, o.obj) {
				return
			}
		}
	}
}

// getWebhookConfig returns the webhooks in the order binding, recording, execMetadata and nodeDebuggingPodMetadata.
func getWebhookConfig(
	execMetadataWebhookEnabled bool,
	operatorNamespace string,
) *admissionregv1.MutatingWebhookConfiguration {
	webhooks := []admissionregv1.MutatingWebhook{
		{
			Name:          binding.name,
			FailurePolicy: &failurePolicyFail,
			// The binding and recording webhooks record events, but not
			// for dry run requests.
			SideEffects:        &sideEffectsNoneOnDryRun,
			TimeoutSeconds:     &timeoutSeconds,
			ReinvocationPolicy: &reinvocationPolicy,
			Rules:              bindingRules,
			NamespaceSelector:  excludeOperatorNamespace(EnableBindingLabel, operatorNamespace),
			ClientConfig: admissionregv1.WebhookClientConfig{
				CABundle: caBundle,
				Service: &admissionregv1.ServiceReference{
					Name: serviceName,
					Path: &binding.path,
				},
			},
			AdmissionReviewVersions: admissionReviewVersions,
		},
		{
			Name:               recording.name,
			FailurePolicy:      &failurePolicyFail,
			SideEffects:        &sideEffectsNoneOnDryRun,
			TimeoutSeconds:     &timeoutSeconds,
			ReinvocationPolicy: &reinvocationPolicy,
			Rules:              recordingRules,
			ObjectSelector:     &excludeOperatorPods,
			NamespaceSelector:  requireLabel(EnableRecordingLabel),
			ClientConfig: admissionregv1.WebhookClientConfig{
				CABundle: caBundle,
				Service: &admissionregv1.ServiceReference{
					Name: serviceName,
					Path: &recording.path,
				},
			},
			AdmissionReviewVersions: admissionReviewVersions,
		},
	}

	if execMetadataWebhookEnabled {
		webhooks = append(webhooks, admissionregv1.MutatingWebhook{
			Name:               execMetadata.name,
			FailurePolicy:      &failurePolicyIgnore,
			SideEffects:        &sideEffects,
			TimeoutSeconds:     &timeoutSeconds,
			ReinvocationPolicy: &reinvocationPolicy,
			Rules:              rulesExec,
			NamespaceSelector:  excludeSystemNamespaces(operatorNamespace),
			ClientConfig: admissionregv1.WebhookClientConfig{
				CABundle: caBundle,
				Service: &admissionregv1.ServiceReference{
					Name: serviceName,
					Path: &execMetadata.path,
				},
			},
			AdmissionReviewVersions: admissionReviewVersions,
		}, admissionregv1.MutatingWebhook{
			Name:               nodeDebuggingPodMetadata.name,
			FailurePolicy:      &failurePolicyIgnore,
			SideEffects:        &sideEffects,
			TimeoutSeconds:     &timeoutSeconds,
			ReinvocationPolicy: &reinvocationPolicy,
			Rules:              rulesNodeDebuggingPod,
			ClientConfig: admissionregv1.WebhookClientConfig{
				CABundle: caBundle,
				Service: &admissionregv1.ServiceReference{
					Name: serviceName,
					Path: &execMetadata.path,
				},
			},
			ObjectSelector:          &objectSelectorNodeDebuggingPod,
			AdmissionReviewVersions: admissionReviewVersions,
		})
	}

	return &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: MutatingWebhookConfigName,
		},
		Webhooks: webhooks,
	}
}

func getValidatingWebhookConfig() *admissionregv1.ValidatingWebhookConfiguration {
	path := rawSelinuxProfileWebhookPath

	return &admissionregv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: ValidatingWebhookConfigName,
		},
		Webhooks: []admissionregv1.ValidatingWebhook{
			{
				Name:           rawSelinuxProfileValidation,
				FailurePolicy:  &failurePolicyFail,
				SideEffects:    &sideEffects,
				TimeoutSeconds: &timeoutSeconds,
				Rules: []admissionregv1.RuleWithOperations{
					{
						Operations: []admissionregv1.OperationType{
							"CREATE", "UPDATE",
						},
						Rule: admissionregv1.Rule{
							APIGroups:   []string{"security-profiles-operator.x-k8s.io"},
							APIVersions: []string{"v1"},
							Resources:   []string{"rawselinuxprofiles"},
							Scope:       &allScopes,
						},
					},
				},
				ClientConfig: admissionregv1.WebhookClientConfig{
					CABundle: caBundle,
					Service: &admissionregv1.ServiceReference{
						Name: serviceName,
						Path: &path,
					},
				},
				AdmissionReviewVersions: admissionReviewVersions,
			},
		},
	}
}

var webhookDeployment = &appsv1.Deployment{
	ObjectMeta: metav1.ObjectMeta{
		Name: webhookName,
	},
	Spec: appsv1.DeploymentSpec{
		Replicas: &replicas,
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				labelApp:  config.OperatorName,
				labelName: webhookName,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					// The webhook needs no privileges, so pin the most
					// restricted SCC on OpenShift.
					openshiftRequiredSCCAnnotation: "restricted-v2",
				},
				Labels: map[string]string{
					labelApp:  config.OperatorName,
					labelName: webhookName,
				},
			},
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				ServiceAccountName: serviceAccountName,
				// The webhooks are fail closed for the namespaces which opt in,
				// so they must not get preempted by other workloads.
				PriorityClassName: webhookPriorityClassName,
				Containers: []corev1.Container{
					{
						Name:            config.OperatorName,
						Args:            []string{"webhook"},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "cert",
								MountPath: certsMountPath,
								ReadOnly:  true,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
							RunAsNonRoot:             &truly,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("32Mi"),
								corev1.ResourceCPU:    resource.MustParse("250m"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("64Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name: config.OperatorNamespaceEnvKey,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "metadata.namespace",
									},
								},
							},
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "webhook",
								ContainerPort: ContainerPort,
								Protocol:      corev1.ProtocolTCP,
							},
							{
								Name:          "health",
								ContainerPort: config.HealthProbePort,
								Protocol:      corev1.ProtocolTCP,
							},
						},
						// The replica only gets admission requests once its
						// webhook server runs and its caches are synced.
						// The values are the defaults of the API server, which
						// have to be set explicitly, because the comparison
						// with the existing deployment does not ignore unset
						// numbers.
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path:   "/readyz",
								Port:   intstr.FromInt32(config.HealthProbePort),
								Scheme: corev1.URISchemeHTTP,
							}},
							TimeoutSeconds:   1,
							PeriodSeconds:    10,
							SuccessThreshold: 1,
							FailureThreshold: 3,
						},
					},
				},
				// Spread the replicas, so that a single node going down does
				// not take the webhook down.
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
							{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											labelApp:  config.OperatorName,
											labelName: webhookName,
										},
									},
									TopologyKey: corev1.LabelHostname,
								},
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "cert",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName:  webhookServerCert,
								DefaultMode: &defaultMode,
							},
						},
					},
				},
				Tolerations: []corev1.Toleration{
					{
						Effect: corev1.TaintEffectNoSchedule,
						Key:    "node-role.kubernetes.io/master",
					},
					{
						Effect: corev1.TaintEffectNoSchedule,
						Key:    "node-role.kubernetes.io/control-plane",
					},
					{
						Effect:   corev1.TaintEffectNoExecute,
						Key:      "node.kubernetes.io/not-ready",
						Operator: corev1.TolerationOpExists,
					},
				},
			},
		},
	},
}

// webhookPDB keeps at least one replica of the fail closed webhooks available
// during voluntary disruptions like node drains. Without it a drain can evict
// all replicas at once, and every pod creation in the namespaces which enable
// binding or recording gets rejected until they come back.
var webhookPDB = &policyv1.PodDisruptionBudget{
	ObjectMeta: metav1.ObjectMeta{
		Name:   webhookName,
		Labels: map[string]string{labelApp: config.OperatorName},
	},
	Spec: policyv1.PodDisruptionBudgetSpec{
		MinAvailable: new(intstr.FromInt32(1)),
		// Crash looping replicas must not block node drains.
		UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				labelApp:  config.OperatorName,
				labelName: webhookName,
			},
		},
	},
}

var webhookService = &corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:   serviceName,
		Labels: map[string]string{labelApp: config.OperatorName},
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Port:       servicePort,
				TargetPort: intstr.FromInt32(ContainerPort),
			},
		},
		Selector: map[string]string{
			labelApp:  config.OperatorName,
			labelName: webhookName,
		},
	},
}
