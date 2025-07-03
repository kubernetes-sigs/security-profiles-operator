/*
Copyright 2022 The Kubernetes Authors.

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
	"reflect"

	"github.com/go-logr/logr"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	replicas                int32 = 3
	defaultMode             int32 = 420
	failurePolicyFail             = admissionregv1.Fail
	failurePolicyIgnore           = admissionregv1.Ignore
	caBundle                      = []byte("Cg==")
	sideEffects                   = admissionregv1.SideEffectClassNone
	admissionReviewVersions       = []string{"v1beta1"}
	rules                         = []admissionregv1.RuleWithOperations{
		{
			Operations: []admissionregv1.OperationType{
				"CREATE", "UPDATE", "DELETE",
			},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods"},
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
			},
		},
	}
	objectSelectorNodeDebuggingPod = metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app.kubernetes.io/managed-by": "kubectl-debug",
		},
	}
	objectSelector = metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "name",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{config.OperatorName, webhookName},
			},
		},
	}
)

const (
	// EnableRecordingLabel this label can be applied to a namespace or a pod
	// in order to enable profile recording.
	EnableRecordingLabel = "spo.x-k8s.io/enable-recording"
	// EnableBindingLabel this label can be applied to a namespace in order to
	// enable profile binding.
	EnableBindingLabel = "spo.x-k8s.io/enable-binding"
)

const (
	webhookName        = config.OperatorName + "-webhook"
	webhookConfigName  = "spo-mutating-webhook-configuration"
	serviceAccountName = "spo-webhook"
	certsMountPath     = "/tmp/k8s-webhook-server/serving-certs"
	serviceName        = "webhook-service"
	webhookServerCert  = "webhook-server-cert"
)

type webhook struct {
	index int
	name  string
	path  string
}

var (
	binding                  = webhook{0, "binding.spo.io", "/mutate-v1-pod-binding"}
	recording                = webhook{1, "recording.spo.io", "/mutate-v1-pod-recording"}
	execMetadata             = webhook{2, "execmetadata.spo.io", "/mutate-v1-exec-metadata"}
	nodeDebuggingPodMetadata = webhook{3, "nodedebuggingpod.spo.io", "/mutate-v1-exec-metadata"}
)

type Webhook struct {
	log        logr.Logger
	deployment *appsv1.Deployment
	config     *admissionregv1.MutatingWebhookConfiguration
	service    *corev1.Service
}

func GetWebhook(
	log logr.Logger,
	namespace string,
	webhookOpts []spodv1alpha1.WebhookOptions,
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

	cfg := getWebhookConfig(execMetadataWebhookEnabled).DeepCopy()
	cfg.Namespace = namespace
	cfg.Webhooks[binding.index].ClientConfig.Service.Namespace = namespace
	cfg.Webhooks[recording.index].ClientConfig.Service.Namespace = namespace

	if execMetadataWebhookEnabled {
		cfg.Webhooks[execMetadata.index].ClientConfig.Service.Namespace = namespace
		cfg.Webhooks[nodeDebuggingPodMetadata.index].ClientConfig.Service.Namespace = namespace
	}

	service := webhookService.DeepCopy()
	service.Namespace = namespace

	switch caInjectType {
	case CAInjectTypeCertManager:
		cfg.Annotations = map[string]string{
			"cert-manager.io/inject-ca-from": config.OperatorName + "/webhook-cert",
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
	applyWebhookOptions(cfg, webhookOpts)

	return &Webhook{
		log:        log,
		deployment: deployment,
		config:     cfg,
		service:    service,
	}
}

func (w *Webhook) Create(ctx context.Context, c client.Client) error {
	for k, o := range w.objectMap() {
		if err := c.Create(ctx, o); err != nil {
			if errors.IsAlreadyExists(err) {
				if k == "config" {
					// The config already exists because it's a global resource we have to remove later on
					if err := c.Patch(ctx, o, client.Merge); err != nil {
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

func applyWebhookOptions(cfg *admissionregv1.MutatingWebhookConfiguration, opts []spodv1alpha1.WebhookOptions) {
	for i := range cfg.Webhooks {
		var userOpt *spodv1alpha1.WebhookOptions

		hook := &cfg.Webhooks[i]

		for j := range opts {
			userOpt = &opts[j]

			if userOpt == nil || userOpt.Name != hook.Name {
				continue
			}

			if userOpt.FailurePolicy != nil {
				hook.FailurePolicy = userOpt.FailurePolicy
			}

			if userOpt.NamespaceSelector != nil {
				hook.NamespaceSelector = userOpt.NamespaceSelector
			}

			if userOpt.ObjectSelector != nil {
				hook.ObjectSelector = userOpt.ObjectSelector
			}
		}
	}
}

func (w *Webhook) NeedsUpdate(ctx context.Context, c client.Client) (bool, error) {
	existingWebHook := admissionregv1.MutatingWebhookConfiguration{}

	if err := c.Get(ctx,
		types.NamespacedName{Namespace: w.config.Namespace, Name: w.config.Name},
		&existingWebHook); err != nil {
		return false, err
	}

	if len(existingWebHook.Webhooks) != len(w.config.Webhooks) {
		w.log.V(1).Info("updating webhook configuration",
			"len(existingWebHook)", len(existingWebHook.Webhooks),
			"len(config)", len(w.config.Webhooks))

		return true, nil
	}

	for i := range existingWebHook.Webhooks {
		ew := existingWebHook.Webhooks[i]

		for j := range w.config.Webhooks {
			cw := w.config.Webhooks[j]

			if ew.Name != cw.Name {
				continue
			}

			if w.webhookNeedsUpdate(&ew, j) {
				w.log.V(1).Info("updating webhook configuration",
					"configName", cw.Name,
					"existingName", ew.Name)

				return true, nil
			}
		}
	}

	return false, nil
}

// only compare the settings that are tunable in spod now.
func (w *Webhook) webhookNeedsUpdate(existing *admissionregv1.MutatingWebhook, index int) bool {
	configured := w.config.Webhooks[index]

	// comparing pointers, not values
	if existing.FailurePolicy == nil && configured.FailurePolicy != nil ||
		existing.FailurePolicy != nil && configured.FailurePolicy == nil {
		w.log.V(1).Info("updating webhook configuration",
			"existing FailurePolicy", existing.FailurePolicy,
			"configured FailurePolicy", configured.FailurePolicy)

		return true
	}

	// comparing values this time
	if existing.FailurePolicy != nil &&
		configured.FailurePolicy != nil &&
		*existing.FailurePolicy != *configured.FailurePolicy {
		w.log.V(1).Info("updating webhook configuration",
			"existing FailurePolicy", existing.FailurePolicy,
			"configured FailurePolicy", configured.FailurePolicy)

		return true
	}

	// Both nil and empty object selector are equal
	// Some platform set the Namespace selector as empty when nil is configured
	if existing.NamespaceSelector != nil && configured.NamespaceSelector == nil {
		if existing.NamespaceSelector.Size() > 0 {
			w.log.V(1).Info("updating webhook configuration",
				"existing NamespaceSelector", existing.NamespaceSelector,
				"configured NamespaceSelector", configured.NamespaceSelector)

			return true
		}
	}

	// comparing pointers, not values
	if existing.NamespaceSelector == nil && configured.NamespaceSelector != nil {
		w.log.V(1).Info("updating webhook configuration",
			"existing NamespaceSelector", existing.NamespaceSelector,
			"configured NamespaceSelector", configured.NamespaceSelector)

		return true
	}

	// Only compare managed labels, all others are out of scope
	if existing.NamespaceSelector != nil && configured.NamespaceSelector != nil {
		for _, label := range []string{EnableBindingLabel, EnableRecordingLabel} {
			if namespaceSelectorUnequalForLabel(label, existing.NamespaceSelector, configured.NamespaceSelector) {
				w.log.V(1).Info("updating webhook configuration",
					"existing NamespaceSelector", existing.NamespaceSelector,
					"configured NamespaceSelector", configured.NamespaceSelector)

				return true
			}
		}
	}

	// Both nil and empty object selector are equal
	if existing.ObjectSelector != nil && configured.ObjectSelector == nil {
		if existing.ObjectSelector.Size() > 0 {
			w.log.V(1).Info("updating webhook configuration",
				"existing ObjectSelector", existing.ObjectSelector,
				"configured ObjectSelector", configured.ObjectSelector)

			return true
		}
	}

	// comparing pointers, not values
	if existing.ObjectSelector == nil && configured.ObjectSelector != nil {
		w.log.V(1).Info("updating webhook configuration",
			"existing ObjectSelector", existing.ObjectSelector,
			"configured ObjectSelector", configured.ObjectSelector)

		return true
	}

	if existing.ObjectSelector != nil &&
		configured.ObjectSelector != nil &&
		!reflect.DeepEqual(*existing.ObjectSelector, *configured.ObjectSelector) {
		w.log.V(1).Info("updating webhook configuration",
			"existing ObjectSelector", existing.ObjectSelector,
			"configured ObjectSelector", configured.ObjectSelector)

		return true
	}

	w.log.V(1).Info("webbhook does not need update")

	return false
}

// namespaceSelectorUnequalForLabel checks if the selected label matches the
// provided LabelSelectors and returns true if they're unequal.
func namespaceSelectorUnequalForLabel(label string, existing, configured *metav1.LabelSelector) bool {
	var (
		i, j                                 int
		existingHasLabel, configuredHasLabel bool
	)

	for i = range existing.MatchExpressions {
		if existing.MatchExpressions[i].Key == label {
			existingHasLabel = true

			break
		}
	}

	for j = range configured.MatchExpressions {
		if configured.MatchExpressions[j].Key == label {
			configuredHasLabel = true

			break
		}
	}

	if existingHasLabel != configuredHasLabel {
		return true
	}

	// Check if values match
	if existingHasLabel && configuredHasLabel &&
		!reflect.DeepEqual(existing.MatchExpressions[i], configured.MatchExpressions[j]) {
		return true
	}

	return false
}

func (w *Webhook) Update(ctx context.Context, c client.Client) error {
	for k, o := range w.objectMap() {
		if err := c.Patch(ctx, o, client.Merge); err != nil {
			return fmt.Errorf("updating %s: %w", k, err)
		}
	}

	return nil
}

func (w *Webhook) objectMap() map[string]client.Object {
	return map[string]client.Object{
		"deployment": w.deployment,
		"config":     w.config,
		"service":    w.service,
	}
}

// getWebhookConfig returns the webhooks in the order binding, recording, execMetadata and nodeDebuggingPodMetadata.
func getWebhookConfig(execMetadataWebhookEnabled bool) *admissionregv1.MutatingWebhookConfiguration {
	webhooks := []admissionregv1.MutatingWebhook{
		{
			Name:           binding.name,
			FailurePolicy:  &failurePolicyFail,
			SideEffects:    &sideEffects,
			Rules:          rules,
			ObjectSelector: &objectSelector,
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      EnableBindingLabel,
						Operator: metav1.LabelSelectorOpExists,
					},
				},
			},
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
			Name:           recording.name,
			FailurePolicy:  &failurePolicyFail,
			SideEffects:    &sideEffects,
			Rules:          rules,
			ObjectSelector: &objectSelector,
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      EnableRecordingLabel,
						Operator: metav1.LabelSelectorOpExists,
					},
				},
			},
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
			Name:          execMetadata.name,
			FailurePolicy: &failurePolicyIgnore,
			SideEffects:   &sideEffects,
			Rules:         rulesExec,
			ClientConfig: admissionregv1.WebhookClientConfig{
				CABundle: caBundle,
				Service: &admissionregv1.ServiceReference{
					Name: serviceName,
					Path: &execMetadata.path,
				},
			},
			AdmissionReviewVersions: admissionReviewVersions,
		}, admissionregv1.MutatingWebhook{
			Name:          nodeDebuggingPodMetadata.name,
			FailurePolicy: &failurePolicyIgnore,
			SideEffects:   &sideEffects,
			Rules:         rulesNodeDebuggingPod,
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
			Name: webhookConfigName,
		},
		Webhooks: webhooks,
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
				"app":  config.OperatorName,
				"name": webhookName,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"openshift.io/scc":             "privileged",
					corev1.SeccompPodAnnotationKey: corev1.SeccompProfileRuntimeDefault,
				},
				Labels: map[string]string{
					"app":  config.OperatorName,
					"name": webhookName,
				},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: serviceAccountName,
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

var webhookService = &corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name:   serviceName,
		Labels: map[string]string{"app": config.OperatorName},
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Port:       servicePort,
				TargetPort: intstr.FromInt32(ContainerPort),
			},
		},
		Selector: map[string]string{
			"app":  config.OperatorName,
			"name": webhookName,
		},
	},
}
