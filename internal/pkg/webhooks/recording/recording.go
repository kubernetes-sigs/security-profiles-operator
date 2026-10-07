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

// reasonConflictingRecording is the reason of the event of a recording which
// does not record a container, because an older one records it already.
const reasonConflictingRecording = "ConflictingRecording"

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

//nolint:gocritic // hugeParam: admission.Handler defines the signature
func (p *podSeccompRecorder) Handle(
	ctx context.Context,
	req admission.Request,
) admission.Response {
	if rec := utils.RecorderForRequest(&req, p.record); rec != p.record {
		dryRun := *p
		dryRun.record = rec
		p = &dryRun
	}

	profileRecordings, err := p.ListProfileRecordings(
		ctx, client.InNamespace(req.Namespace),
	)
	if err != nil {
		p.log.Error(err, "Could not list profile recordings")

		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Recording relies on Linux facilities, so Windows pods are skipped.
	pod, podName, resp := utils.DecodePod(p.decoder, &req, p.log)
	if resp != nil {
		return *resp
	}

	isCreate := req.Operation == admissionv1.Create

	// A recording only starts with the pod. On any other operation the
	// annotations of the old pod are the ones to keep, so that a recording
	// created later does not start on a pod which is already running, and
	// removing or changing the annotation cannot rename the recorded profile.
	oldPod := &corev1.Pod{}

	if !isCreate && len(req.OldObject.Raw) > 0 {
		if err := p.decoder.DecodeRaw(req.OldObject, oldPod); err != nil {
			p.log.Error(err, "Failed to decode old pod")

			return admission.Errored(http.StatusBadRequest, err)
		}
	}

	podChanged := false
	podLabels := labels.Set(pod.GetLabels())

	// Recordings which select the same container conflict. The oldest one
	// records it, independent of the order of the cache.
	items := slices.Clone(profileRecordings.Items)
	slices.SortStableFunc(items, func(a, b profilerecordingapi.ProfileRecording) int {
		if c := a.CreationTimestamp.Compare(b.CreationTimestamp.Time); c != 0 {
			return c
		}

		return strings.Compare(a.Name, b.Name)
	})

	// claimed maps the annotation keys set by this admission to the recording
	// which set them. On update, a container stays with the recording which
	// started recording it, even if the labels select an older one now.
	claimed := map[string]string{}
	if !isCreate {
		claimed = ownersOfRecordedContainers(items, pod, oldPod)
	}

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

		// An invalid selector of one recording must not block all pods in
		// the namespace, so the recording gets skipped instead.
		selector, err := metav1.LabelSelectorAsSelector(item.Spec.PodSelector)
		if err != nil {
			p.log.Error(err, "Invalid podSelector, skipping profile recording",
				"recording", item.Name,
			)
			p.record.Eventf(
				&item,
				nil,
				corev1.EventTypeWarning,
				"InvalidPodSelector",
				util.EventActionMutate,
				"The recording was skipped for a pod, because its podSelector is invalid: %v",
				err,
			)

			continue
		}

		if selector.Matches(podLabels) {
			changed, err := p.updatePod(pod, oldPod, podName, &item, isCreate, claimed)
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

	// The patch only touches the mutated fields, so that the fields of the
	// pod which the vendored pod type does not know are kept.
	return utils.PodPatchResponse(p.decoder, &req, pod)
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

// updatePod applies the recording to the containers of the pod. On creation
// the containers get their security context and a fresh recording annotation.
// Otherwise oldPod is the pod before the update: only annotations which
// already exist on it are kept up, with their value, and no new recording is
// started.
func (p *podSeccompRecorder) updatePod(
	pod, oldPod *corev1.Pod,
	podName string,
	profileRecording *profilerecordingapi.ProfileRecording,
	isCreate bool,
	claimed map[string]string,
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

		if owner, ok := claimed[key]; ok && owner != profileRecording.Name {
			p.log.Info("container is recorded by another recording already",
				"pod", podName, "container", ctr.Name, "recording", owner)

			// Reported when the pod gets created, not with every update.
			if !isCreate {
				continue
			}

			p.record.Eventf(
				profileRecording,
				nil,
				corev1.EventTypeWarning,
				reasonConflictingRecording,
				util.EventActionMutate,
				"Container %s of pod %s is recorded by the older recording %s",
				ctr.Name, podName, owner,
			)

			continue
		}

		claimed[key] = profileRecording.Name

		// Container security contexts are immutable after creation, so they
		// can only be set on CREATE. Mutating them on UPDATE would produce a
		// patch the API server rejects, which blocks any further pod update.
		if isCreate {
			p.warnEventIfContainerPrivileged(profileRecording, ctr, podName)

			p.updateSecurityContext(ctr, profileRecording)
		} else {
			oldValue, existed := oldPod.GetAnnotations()[key]
			if !existed {
				// The pod predates the recording, or did not match it on
				// creation, so it is not being recorded.
				continue
			}

			// The value carries a random nonce and a timestamp, so a fresh
			// one would rename the recorded profile. Keep the value the
			// recording started with, unless it is not one of this
			// recording and container.
			if isRecordingAnnotationValue(oldValue, profileRecording.Name, ctr.Name) {
				value = oldValue
			}
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

		// Overwrite a value which is not one of this recording and
		// container, to avoid that an attacker spoofs a profile recording
		// into its own controlled profile instead of the one expected. On
		// creation the value carries a fresh nonce and timestamp, so a value
		// of the recording is kept as it is, otherwise every admission would
		// rename the recorded profile. On update the value is the one of the
		// old pod, so a changed nonce gets reverted as well.
		if existingValue == value ||
			(isCreate && isRecordingAnnotationValue(existingValue, profileRecording.Name, ctr.Name)) {
			continue
		}

		pod.Annotations[key] = value
		podChanged = true

		p.log.Info("workload already has annotation, overwriting",
			"workload", podName, "existingValue", existingValue, "newValue", value)
	}

	return podChanged, nil
}

// ownersOfRecordedContainers returns the recordings which record the
// containers of the pod, by the annotation keys of the old pod.
func ownersOfRecordedContainers(
	recordings []profilerecordingapi.ProfileRecording, pod, oldPod *corev1.Pod,
) map[string]string {
	owners := map[string]string{}

	ctrs := slices.Concat(pod.Spec.InitContainers, pod.Spec.Containers)

	for i := range recordings {
		recording := &recordings[i]

		for j := range ctrs {
			name := ctrs[j].Name

			key, _, err := recording.CtrAnnotation(name)
			if err != nil {
				continue
			}

			if isRecordingAnnotationValue(oldPod.GetAnnotations()[key], recording.Name, name) {
				owners[key] = recording.Name
			}
		}
	}

	return owners
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
		// Handle skips the logs recorder for AppArmor, see
		// ValidateRecorderKindCombination.
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

func (p *podSeccompRecorder) warnEventIfContainerPrivileged(
	profileRecording *profilerecordingapi.ProfileRecording,
	ctr *corev1.Container,
	podName string,
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
		"Container %s of pod %s is privileged, so it runs without the profile which the "+
			"log based recording relies on and does not get recorded. "+
			"Use the bpf recorder to record privileged containers",
		ctr.Name,
		podName,
	)
}

// warnEventIfNameTooLong warns the user if the name of the profile recording
// cannot be used as the value of the recording label on the recorded
// profiles, which is the case for names longer than 63 characters. The CRD
// rejects such names for new recordings, so this only concerns recordings
// which predate the rule.
func (p *podSeccompRecorder) warnEventIfNameTooLong(
	profileRecording *profilerecordingapi.ProfileRecording,
) {
	errs := validation.IsValidLabelValue(profileRecording.Name)
	if len(errs) == 0 {
		return
	}

	p.record.Eventf(profileRecording,
		nil,
		corev1.EventTypeWarning,
		"NameNotLabelValue",
		util.EventActionMutate,
		"The recording name %s can't be used as a label value on the recorded profiles: %s",
		profileRecording.Name,
		strings.Join(errs, ","))
}
