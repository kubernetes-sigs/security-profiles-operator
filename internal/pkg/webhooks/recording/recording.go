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
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilerecordingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

const finalizer = "active-seccomp-profile-recording-lock"

type podSeccompRecorder struct {
	impl
	log      logr.Logger
	replicas sync.Map
}

func RegisterWebhook(server *webhook.Server, c client.Client) {
	server.Register(
		"/mutate-v1-pod-recording",
		&webhook.Admission{
			Handler: &podSeccompRecorder{
				impl: &defaultImpl{client: c},
				log:  logf.Log.WithName("recording"),
			},
		},
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
	profileRecordings, err := p.impl.ListProfileRecordings(
		ctx, client.InNamespace(req.Namespace),
	)
	if err != nil {
		p.log.Error(err, "Could not list profile recordings")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	podChanged := false
	pod := &corev1.Pod{}
	if req.Operation != admissionv1.Delete {
		pod, err = p.impl.DecodePod(req)
		if err != nil {
			p.log.Error(err, "Failed to decode pod")
			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	podName := req.Name
	if podName == "" {
		podName = pod.GenerateName
	}

	podLabels := labels.Set(pod.GetLabels())
	items := profileRecordings.Items

	for i := range items {
		item := items[i]
		if item.Spec.Kind != "SeccompProfile" {
			p.log.Info(fmt.Sprintf(
				"recording kind %s not supported", item.Spec.Kind,
			))
			continue
		}

		selector, err := p.impl.LabelSelectorAsSelector(
			&item.Spec.PodSelector,
		)
		if err != nil {
			p.log.Error(
				err, "Could not get label selector from profile recording",
			)
			return admission.Errored(http.StatusInternalServerError, err)
		}

		if req.Operation == admissionv1.Delete {
			p.cleanupReplicas(podName)
			if err := p.removePod(ctx, podName, &item); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			continue
		}

		if selector.Matches(podLabels) {
			podChanged = p.addAnnotations(pod, &item)
		}

		if podChanged {
			if err := p.addPod(ctx, podName, &item); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
		}
	}

	if !podChanged {
		return admission.Allowed("pod unchanged")
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		p.log.Error(err, "Failed to encode pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (p *podSeccompRecorder) addAnnotations(
	pod *corev1.Pod,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
) (podChanged bool) {
	ctrs := []corev1.Container{}
	ctrs = append(ctrs, pod.Spec.InitContainers...)
	ctrs = append(ctrs, pod.Spec.Containers...)

	// Handle replicas by tracking them
	replica := ""
	if pod.Name == "" && pod.GenerateName != "" {
		v, _ := p.replicas.LoadOrStore(pod.GenerateName, uint(0))
		replica = fmt.Sprintf("-%d", v)
		p.replicas.Store(pod.GenerateName, v.(uint)+1)
	}

	for i := range ctrs {
		ctr := &ctrs[i]
		key := fmt.Sprintf("%s/%s", config.SeccompProfileRecordAnnotationKey, ctr.Name)

		ctrName := ctr.Name
		if replica != "" {
			ctrName += replica
		}

		value := fmt.Sprintf(
			"of:%s/%s-%s-%d.json",
			config.ProfileRecordingOutputPath,
			profileRecording.GetName(),
			ctrName,
			time.Now().Unix(),
		)

		existingValue, ok := pod.GetAnnotations()[key]
		if !ok {
			if pod.Annotations == nil {
				pod.Annotations = make(map[string]string)
			}
			pod.Annotations[key] = value
			p.log.Info(fmt.Sprintf(
				"adding seccomp recording annotation %s=%s to pod %s",
				key, value, pod.Name,
			))
			podChanged = true
			continue
		}

		if existingValue != value {
			p.log.Error(
				errors.New("existing annotation"),
				fmt.Sprintf(
					"workload %s already has annotation %s (not mutating to %s).",
					pod.Name,
					existingValue,
					value,
				),
			)
		}
	}

	return podChanged
}

func (p *podSeccompRecorder) cleanupReplicas(podName string) {
	p.replicas.Range(func(key, _ interface{}) bool {
		if strings.HasPrefix(podName, key.(string)) {
			p.replicas.Delete(key)
			return false
		}
		return true
	})
}

func (p *podSeccompRecorder) addPod(
	ctx context.Context,
	podName string,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
) error {
	profileRecording.Status.ActiveWorkloads = utils.AppendIfNotExists(
		profileRecording.Status.ActiveWorkloads, podName,
	)

	if err := p.impl.UpdateResource(
		ctx, p.log, profileRecording, "profilerecording status",
	); err != nil {
		return errors.Wrap(err, "update resource on adding pod")
	}

	if !controllerutil.ContainsFinalizer(profileRecording, finalizer) {
		controllerutil.AddFinalizer(profileRecording, finalizer)
	}

	return p.impl.UpdateResource(ctx, p.log, profileRecording, "profilerecording")
}

func (p *podSeccompRecorder) removePod(
	ctx context.Context,
	podName string,
	profileRecording *profilerecordingv1alpha1.ProfileRecording,
) error {
	newActiveWorkloads := []string{}
	for _, activeWorkload := range profileRecording.Status.ActiveWorkloads {
		if !strings.HasPrefix(podName, activeWorkload) {
			newActiveWorkloads = append(newActiveWorkloads, activeWorkload)
		}
	}
	profileRecording.Status.ActiveWorkloads = newActiveWorkloads

	if err := p.impl.UpdateResource(
		ctx, p.log, profileRecording, "profilerecording status",
	); err != nil {
		return errors.Wrap(err, "update resource on removing pod")
	}

	if len(profileRecording.Status.ActiveWorkloads) == 0 &&
		controllerutil.ContainsFinalizer(profileRecording, finalizer) {
		controllerutil.RemoveFinalizer(profileRecording, finalizer)
	}

	return p.impl.UpdateResource(ctx, p.log, profileRecording, "profilerecording")
}

func (p *podSeccompRecorder) InjectDecoder(decoder *admission.Decoder) error {
	p.impl.SetDecoder(decoder)
	return nil
}
