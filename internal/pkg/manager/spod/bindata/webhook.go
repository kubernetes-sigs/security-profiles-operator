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
	failurePolicy                 = admissionregv1.Fail
	caBundle                      = []byte("Cg==")
	bindingPath                   = "/mutate-v1-pod-binding"
	recordingPath                 = "/mutate-v1-pod-recording"
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

	cfg := webhookConfig.DeepCopy()
	cfg.Namespace = namespace
	cfg.Webhooks[0].ClientConfig.Service.Namespace = namespace
	cfg.Webhooks[1].ClientConfig.Service.Namespace = namespace

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
		return true, nil
	}

	for i := range existingWebHook.Webhooks {
		ew := existingWebHook.Webhooks[i]

		for j := range w.config.Webhooks {
			cw := w.config.Webhooks[j]

			if ew.Name != cw.Name {
				continue
			}

			if webhookNeedsUpdate(&ew, &cw) {
				return true, nil
			}
		}
	}

	return false, nil
}

// only compare the settings that are tunable in spod now.
func webhookNeedsUpdate(existing, configured *admissionregv1.MutatingWebhook) bool {
	if existing.FailurePolicy == nil && configured.FailurePolicy != nil ||
		existing.FailurePolicy != nil && configured.FailurePolicy == nil {
		// comparing pointers, not values
		return true
	}

	if existing.FailurePolicy != nil &&
		configured.FailurePolicy != nil &&
		*existing.FailurePolicy != *configured.FailurePolicy {
		// comparing values this time
		return true
	}

	if existing.NamespaceSelector == nil && configured.NamespaceSelector != nil ||
		existing.NamespaceSelector != nil && configured.NamespaceSelector == nil {
		// comparing pointers, not values
		return true
	}

	if existing.NamespaceSelector != nil && configured.NamespaceSelector != nil {
		// Only compare managed labels, all others are out of scope
		for _, label := range []string{EnableBindingLabel, EnableRecordingLabel} {
			if namespaceSelectorUnequalForLabel(label, existing.NamespaceSelector, configured.NamespaceSelector) {
				return true
			}
		}
	}

	if existing.ObjectSelector == nil && configured.ObjectSelector != nil ||
		existing.ObjectSelector != nil && configured.ObjectSelector == nil {
		// comparing pointers, not values
		return true
	}

	if existing.ObjectSelector != nil &&
		configured.ObjectSelector != nil &&
		!reflect.DeepEqual(*existing.ObjectSelector, *configured.ObjectSelector) {
		return true
	}

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

var webhookConfig = &admissionregv1.MutatingWebhookConfiguration{
	ObjectMeta: metav1.ObjectMeta{
		Name: webhookConfigName,
	},
	Webhooks: []admissionregv1.MutatingWebhook{
		{
			Name:           "binding.spo.io",
			FailurePolicy:  &failurePolicy,
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
					Path: &bindingPath,
				},
			},
			AdmissionReviewVersions: admissionReviewVersions,
		},
		{
			Name:           "recording.spo.io",
			FailurePolicy:  &failurePolicy,
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
					Path: &recordingPath,
				},
			},
			AdmissionReviewVersions: admissionReviewVersions,
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
