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

package recording

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

type podSeccompRecorder struct {
	impl
	decoder admission.Decoder
	log     logr.Logger
	record  *utils.SafeRecorder
}

func RegisterWebhook(
	server webhook.Server,
	scheme *runtime.Scheme,
	rec util.EventRecorder,
	c client.Client,
) {
	server.Register(
		"/mutate-v1-pod-recording",
		&webhook.Admission{
			Handler: &podSeccompRecorder{
				impl:    &defaultImpl{client: c},
				decoder: admission.NewDecoder(scheme),
				log:     logf.Log.WithName("recording"),
				record:  utils.NewSafeRecorder(rec),
			},
		},
	)
}

// Security Profiles Operator Webhook RBAC permissions
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

//nolint:gocritic // hugeParam: admission.Handler defines the signature
func (p *podSeccompRecorder) Handle(
	ctx context.Context,
	req admission.Request,
) admission.Response {
	profileRecordings, err := p.ListProfileRecordings(
		ctx, client.InNamespace(req.Namespace),
	)
	if err != nil {
		p.log.Error(err, "Could not list profile recordings")

		return admission.Errored(http.StatusInternalServerError, err)
	}

	pod := &corev1.Pod{}
	if err := p.decoder.Decode(req, pod); err != nil {
		p.log.Error(err, "Failed to decode pod")

		return admission.Errored(http.StatusBadRequest, err)
	}

	podName := req.Name
	if podName == "" {
		podName = pod.GenerateName
	}

	podChanged := false
	podLabels := labels.Set(pod.GetLabels())
	items := profileRecordings.Items

	for i := range items {
		item := items[i]
		if !item.IsKindSupported() {
			p.log.Info("recording kind not supported", "kind", item.Spec.Kind)

			continue
		}

		if err := item.ValidateRecorderKindCombination(); err != nil {
			p.log.Error(err, "Invalid recorder/kind combination",
				"recording", item.Name,
			)

			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(item.Spec.PodSelector)
		if err != nil {
			p.log.Error(
				err, "Could not get label selector from profile recording",
			)

			return admission.Errored(http.StatusBadRequest, err)
		}

		if selector.Matches(podLabels) {
			changed, err := p.updatePod(pod, podName, &item, req.Operation == admissionv1.Create)
			if err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}

			if changed {
				podChanged = true
			}

			// for any matched pod, check the name of the recording in case the recording
			// is mergeable - in that case, the recording name will be used as a label
			p.warnEventIfNameTooLong(&item)
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

func (p *podSeccompRecorder) shouldRecordContainer(containerName string,
	profileRecording *profilerecordingapi.ProfileRecording,
) bool {
	// Allow all containers when no containers are explicitly listed
	if profileRecording.Spec.Containers == nil {
		return true
	}

	return slices.Contains(profileRecording.Spec.Containers, containerName)
}

func (p *podSeccompRecorder) updatePod(
	pod *corev1.Pod,
	podName string,
	profileRecording *profilerecordingapi.ProfileRecording,
	isCreate bool,
) (podChanged bool, err error) {
	// Collect containers as references to not copy them during modification
	ctrs := []*corev1.Container{}

	for i := range pod.Spec.InitContainers {
		if p.shouldRecordContainer(pod.Spec.InitContainers[i].Name, profileRecording) {
			ctrs = append(ctrs, &pod.Spec.InitContainers[i])
		}
	}

	for i := range pod.Spec.Containers {
		if p.shouldRecordContainer(pod.Spec.Containers[i].Name, profileRecording) {
			ctrs = append(ctrs, &pod.Spec.Containers[i])
		}
	}

	for i := range ctrs {
		ctr := ctrs[i]

		key, value, err := profileRecording.CtrAnnotation(ctr.Name)
		if err != nil {
			return false, err
		}

		// Container security contexts are immutable after creation, so they
		// can only be set on CREATE. Mutating them on UPDATE would produce a
		// patch the API server rejects, which blocks any further pod update.
		if isCreate {
			p.warnEventIfContainerPrivileged(profileRecording, ctr, pod)

			p.updateSecurityContext(ctr, profileRecording)
		}

		existingValue, ok := pod.GetAnnotations()[key]
		if !ok {
			if pod.Annotations == nil {
				pod.Annotations = make(map[string]string)
			}

			pod.Annotations[key] = value
			p.log.Info("adding recording annotation to pod",
				"key", key, "value", value, "pod", pod.Name)

			podChanged = true

			continue
		}

		// The value carries a random nonce and a timestamp, so it differs on
		// every admission. Keep a value of this recording and container,
		// otherwise every pod update would rename the recorded profile.
		if !isRecordingAnnotationValue(existingValue, profileRecording.Name, ctr.Name) {
			// Overwrite the existing value with the expected value to avoid that
			// an attacker will spoof a profile recording into its own controlled
			// profile instead of the one expected.
			pod.Annotations[key] = value
			podChanged = true

			p.log.Info("workload already has annotation, overwriting",
				"workload", podName, "existingValue", existingValue, "newValue", value)
		}
	}

	return podChanged, nil
}

// isRecordingAnnotationValue returns true if the annotation value has the
// format "<recording>_<container>_<nonce>_<timestamp>" for the provided
// recording and container. The profile name is derived only from the recording
// and container, so such a value cannot redirect the recorded profile.
func isRecordingAnnotationValue(value, recordingName, ctrName string) bool {
	suffix, ok := strings.CutPrefix(value, recordingName+"_"+ctrName+"_")
	if !ok {
		return false
	}

	nonce, timestamp, ok := strings.Cut(suffix, "_")

	return ok && nonce != "" && timestamp != "" && !strings.Contains(timestamp, "_")
}

func (p *podSeccompRecorder) updateSecurityContext(
	ctr *corev1.Container, pr *profilerecordingapi.ProfileRecording,
) {
	if pr.Spec.Recorder != profilerecordingapi.ProfileRecorderLogs {
		// we only need to ensure the special security context if we're tailing
		// the logs
		return
	}

	switch pr.Spec.Kind {
	case profilerecordingapi.ProfileRecordingKindSeccompProfile:
		p.updateSeccompSecurityContext(ctr, pr)
	case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
		p.updateSelinuxSecurityContext(ctr, pr)
	case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
		p.updateApparmorSecurityContext(ctr, pr)
	}

	p.log.Info("set SecurityContext for container",
		"container", ctr.Name, "securityContext", ctr.SecurityContext)
}

func (p *podSeccompRecorder) updateSeccompSecurityContext(
	ctr *corev1.Container,
	pr *profilerecordingapi.ProfileRecording,
) {
	if ctr.SecurityContext == nil {
		ctr.SecurityContext = &corev1.SecurityContext{}
	}

	if ctr.SecurityContext.SeccompProfile == nil {
		ctr.SecurityContext.SeccompProfile = &corev1.SeccompProfile{}
	} else {
		p.record.Eventf(
			pr,
			nil,
			corev1.EventTypeWarning,
			"SecurityContextAlreadySet",
			util.EventActionMutate,
			"Container %s had SecurityContext already set, the profile recorder overwrote it",
			ctr.Name,
		)
	}

	ctr.SecurityContext.SeccompProfile.Type = corev1.SeccompProfileTypeLocalhost
	// Seccomp profiles are cluster scoped, so the file of the log enricher
	// profile has no namespace directory.
	profile := path.Join(
		config.OperatorProfilesFolder,
		config.LogEnricherProfile+seccompprofileapi.ExtJSON,
	)
	ctr.SecurityContext.SeccompProfile.LocalhostProfile = &profile
}

func (p *podSeccompRecorder) updateSelinuxSecurityContext(
	ctr *corev1.Container,
	pr *profilerecordingapi.ProfileRecording,
) {
	if ctr.SecurityContext == nil {
		ctr.SecurityContext = &corev1.SecurityContext{}
	}

	if ctr.SecurityContext.SELinuxOptions == nil {
		ctr.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{}
	} else {
		p.record.Eventf(
			pr,
			nil,
			corev1.EventTypeWarning,
			"SecurityContextAlreadySet",
			util.EventActionMutate,
			"Container %s had SecurityContext already set, the profile recorder overwrote it",
			ctr.Name,
		)
	}

	ctr.SecurityContext.SELinuxOptions.Type = config.SelinuxPermissiveProfile
}

func (p *podSeccompRecorder) updateApparmorSecurityContext(
	ctr *corev1.Container,
	pr *profilerecordingapi.ProfileRecording,
) {
	if pr.Spec.Recorder != profilerecordingapi.ProfileRecorderLogs {
		return
	}

	p.record.Eventf(pr,
		nil,
		corev1.EventTypeWarning,
		"AppArmorNotSupported",
		util.EventActionMutate,
		"AppArmor log-based recording is not supported, container: %s", ctr.Name)
}

func (p *podSeccompRecorder) warnEventIfContainerPrivileged(
	profileRecording *profilerecordingapi.ProfileRecording,
	ctr *corev1.Container,
	pod *corev1.Pod,
) {
	if profileRecording.Spec.Recorder != profilerecordingapi.ProfileRecorderLogs {
		return
	}

	if ctr.SecurityContext == nil || ctr.SecurityContext.Privileged == nil ||
		!*ctr.SecurityContext.Privileged {
		return
	}

	p.record.Eventf(
		profileRecording,
		nil,
		corev1.EventTypeWarning,
		"PrivilegedContainer",
		util.EventActionMutate,
		"Container %s in pod %s is privileged, cannot use log-based profile recording",
		ctr.Name,
		pod.Name,
	)
}

// warnEventIfNameTooLong warns the user if the name of the profile recording is too long or otherwise does
// not conform to the Kubernetes naming conventions for labels.
func (p *podSeccompRecorder) warnEventIfNameTooLong(
	profileRecording *profilerecordingapi.ProfileRecording,
) {
	errs := validation.IsDNS1123Label(profileRecording.Name)
	if len(errs) == 0 {
		return
	}

	p.record.Eventf(profileRecording,
		nil,
		corev1.EventTypeWarning,
		"NameNotDNSLabel",
		util.EventActionMutate,
		"The recording name %s is not a DNS1123 label and can't be used as a label: %s",
		profileRecording.Name,
		strings.Join(errs, ","))
}
