/*
Copyright 2021 The Kubernetes Authors.

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

package recording

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilerecordingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const finalizer = "active-seccomp-profile-recording-lock"

var log = logf.Log.WithName("pod-resource")

type podSeccompRecorder struct {
	client  client.Client
	decoder *admission.Decoder
}

func RegisterWebhook(server *webhook.Server, c client.Client) {
	server.Register(
		"/mutate-v1-pod-recording",
		&webhook.Admission{Handler: &podSeccompRecorder{client: c}},
	)
}

// nolint:lll
// Security Profiles Operator Webhook RBAC permissions
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// nolint:lll
// Leader election
// +kubebuilder:rbac:groups=core,namespace="security-profiles-operator",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace="security-profiles-operator",resources=leases,verbs=create;get;update;

// nolint:gocritic
func (p *podSeccompRecorder) Handle(
	ctx context.Context,
	req admission.Request,
) admission.Response {
	profileRecordings := &profilerecordingv1alpha1.ProfileRecordingList{}
	if err := p.client.List(
		ctx, profileRecordings, client.InNamespace(req.Namespace),
	); err != nil {
		log.Error(err, "Could not list profile recordings")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	podChanged := false
	podID := req.Namespace + "/" + req.Name
	pod := &corev1.Pod{}

	if req.Operation != admissionv1.Delete {
		err := p.decoder.Decode(req, pod)
		if err != nil {
			log.Error(err, "Failed to decode pod")
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	podLabels := labels.Set(pod.GetLabels())
	items := profileRecordings.Items

	for i := range items {
		if items[i].Spec.Kind != "SeccompProfile" {
			log.Info(fmt.Sprintf(
				"recording kind %s not supported", items[i].Spec.Kind,
			))
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(
			&items[i].Spec.PodSelector,
		)
		if err != nil {
			log.Error(
				err, "Could not get label selector from profile recording",
			)
			return admission.Errored(http.StatusInternalServerError, err)
		}

		if req.Operation == admissionv1.Delete {
			if err := p.removePod(ctx, podID, &items[i]); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			continue
		}

		if selector.Matches(podLabels) {
			podChanged = p.addAnnotation(pod, &items[i])
		}

		if podChanged {
			if err := p.addPod(ctx, podID, &items[i]); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
		}
	}

	if !podChanged {
		return admission.Allowed("pod unchanged")
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		log.Error(err, "Failed to encode pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (p *podSeccompRecorder) addAnnotation(
	pod *corev1.Pod,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
) (podChanged bool) {
	value, ok := pod.GetAnnotations()[config.SeccompProfileRecordAnnotationKey]

	targetValue := fmt.Sprintf(
		"of:%s/%s-%d.json",
		config.ProfileRecordingOutputPath,
		profileRecording.GetName(),
		time.Now().Unix(),
	)

	if !ok {
		if pod.Annotations == nil {
			pod.Annotations = make(map[string]string)
		}
		pod.Annotations[config.SeccompProfileRecordAnnotationKey] = targetValue
		log.Info("adding seccomp recording annotation to pod", "Pod", pod.Name)
		return true
	}

	if value != targetValue {
		log.Error(
			errors.New("existing annotation"),
			fmt.Sprintf(
				"Workload %s already has annotation %s (not mutating to %s).",
				pod.Name,
				value,
				targetValue,
			),
		)
	}

	return false
}

func (p *podSeccompRecorder) addPod(
	ctx context.Context,
	podID string,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
) error {
	profileRecording.Status.ActiveWorkloads = appendIfNotExists(
		profileRecording.Status.ActiveWorkloads, podID,
	)

	if err := updateResource(
		ctx, p.client.Status(), profileRecording, "profilerecording status",
	); err != nil {
		return errors.Wrap(err, "update resource on adding pod")
	}

	if !controllerutil.ContainsFinalizer(profileRecording, finalizer) {
		controllerutil.AddFinalizer(profileRecording, finalizer)
	}

	return updateResource(ctx, p.client, profileRecording, "profilerecording")
}

func (p *podSeccompRecorder) removePod(
	ctx context.Context,
	podID string,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
) error {
	profileRecording.Status.ActiveWorkloads = removeIfExists(
		profileRecording.Status.ActiveWorkloads, podID,
	)

	if err := updateResource(
		ctx, p.client.Status(), profileRecording, "profilerecording status",
	); err != nil {
		return errors.Wrap(err, "update resource on removing pod")
	}

	if len(profileRecording.Status.ActiveWorkloads) == 0 &&
		controllerutil.ContainsFinalizer(profileRecording, finalizer) {
		controllerutil.RemoveFinalizer(profileRecording, finalizer)
	}

	return updateResource(ctx, p.client, profileRecording, "profilerecording")
}

func appendIfNotExists(list []string, item string) []string {
	for _, s := range list {
		if s == item {
			return list
		}
	}
	return append(list, item)
}

func removeIfExists(list []string, item string) []string {
	for i := range list {
		if list[i] == item {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

func updateResource(
	ctx context.Context,
	c client.StatusWriter,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
	resource string,
) error {
	if err := c.Update(ctx, profileRecording); err != nil {
		msg := fmt.Sprintf("failed to update %s", resource)
		log.Error(err, msg)
		return errors.Wrap(err, msg)
	}
	return nil
}

func (p *podSeccompRecorder) InjectDecoder(d *admission.Decoder) error {
	p.decoder = d
	return nil
}
