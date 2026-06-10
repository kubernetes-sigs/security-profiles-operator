/*
Copyright 2020 The Kubernetes Authors.

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

package v1

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

type ProfileRecordingKind string

const (
	ProfileRecordingKindSeccompProfile  ProfileRecordingKind = "SeccompProfile"
	ProfileRecordingKindSelinuxProfile  ProfileRecordingKind = "SelinuxProfile"
	ProfileRecordingKindAppArmorProfile ProfileRecordingKind = "AppArmorProfile"
)

type ProfileRecorder string

const (
	ProfileRecorderLogs ProfileRecorder = "Logs"
	ProfileRecorderBpf  ProfileRecorder = "Bpf"
)

type ProfileMergeStrategy string

const (
	ProfileMergeNone       ProfileMergeStrategy = "None"
	ProfileMergeContainers ProfileMergeStrategy = "Containers"
)

const (
	// ProfileToRecordingLabel is the name of the ProfileRecording CR that produced this profile.
	ProfileToRecordingLabel = "spo.x-k8s.io/recording-id"
	// ProfileToRecordingNamespaceLabel is the namespace of the ProfileRecording CR that produced this profile.
	// Required to disambiguate cluster-scoped profiles from recordings with the same name in different namespaces.
	ProfileToRecordingNamespaceLabel = "spo.x-k8s.io/recording-namespace"
	// ProfileToContainerLabel is the name of the container that produced this profile.
	ProfileToContainerLabel = "spo.x-k8s.io/container-id"
	// RecordingHasUnmergedProfiles is a finalizer that indicates that the recording has partial policies. Its
	// main use is to hold off the deletion of the recording until all partial profiles are merged.
	RecordingHasUnmergedProfiles = "spo.x-k8s.io/has-unmerged-profiles"
)

// ProfileRecordingSpec defines the desired state of ProfileRecording.
type ProfileRecordingSpec struct {
	// kind specifies the type of object to be recorded.
	// +required
	// +kubebuilder:validation:Enum=SeccompProfile;SelinuxProfile;AppArmorProfile
	Kind ProfileRecordingKind `json:"kind,omitempty"`

	// recorder specifies which recorder to use.
	// +required
	// +kubebuilder:validation:Enum=Bpf;Logs
	Recorder ProfileRecorder `json:"recorder,omitempty"`

	// mergeStrategy controls whether or how to merge recorded profiles.
	// Can be one of "None" or "Containers". Default is "None".
	// +optional
	// +default="None"
	// +kubebuilder:validation:Enum=None;Containers
	MergeStrategy ProfileMergeStrategy `json:"mergeStrategy,omitempty"`

	// podSelector selects the pods to record. This field follows standard
	// label selector semantics. An empty podSelector matches all pods in this
	// namespace.
	// +required
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// containers is a set of containers to record. This allows to select
	// only specific containers to record instead of all containers present
	// in the pod.
	// +optional
	// +listType=set
	Containers []string `json:"containers,omitempty"`

	// disableProfileAfterRecording indicates whether the profile should be
	// disabled after recording and thus skipped during reconcile. In case of
	// SELinux profiles, reconcile can take a significant amount of time and
	// for all profiles might not be needed. Defaults to false.
	// +optional
	// +default=false
	DisableProfileAfterRecording bool `json:"disableProfileAfterRecording,omitempty"`
}

// ProfileRecordingStatus contains status of the ProfileRecording.
type ProfileRecordingStatus struct {
	// activeWorkloads lists the workloads currently using this recording.
	// +optional
	// +listType=set
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
}

// +kubebuilder:object:root=true

// ProfileRecording is the Schema for the profilerecordings API.
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="PodSelector",type=string,priority=10,JSONPath=`.spec.podSelector`
type ProfileRecording struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the ProfileRecording.
	// +required
	Spec ProfileRecordingSpec `json:"spec,omitzero"`
	// status contains the observed state of the ProfileRecording.
	// +optional
	Status ProfileRecordingStatus `json:"status,omitempty"`
}

func (pr *ProfileRecording) CtrAnnotation(ctrName string) (key, value string, err error) {
	switch pr.Spec.Kind {
	case ProfileRecordingKindSeccompProfile:
		return pr.ctrAnnotationSeccomp(ctrName)
	case ProfileRecordingKindSelinuxProfile:
		return pr.ctrAnnotationSelinux(ctrName)
	case ProfileRecordingKindAppArmorProfile:
		return pr.ctrAnnotationApparmor(ctrName)
	default:
		return "", "", fmt.Errorf(
			"invalid kind: %s", pr.Spec.Kind,
		)
	}
}

func (pr *ProfileRecording) IsKindSupported() bool {
	switch pr.Spec.Kind {
	case ProfileRecordingKindSelinuxProfile,
		ProfileRecordingKindSeccompProfile,
		ProfileRecordingKindAppArmorProfile:
		return true
	default:
		return false
	}
}

func (pr *ProfileRecording) ValidateRecorderKindCombination() error {
	switch pr.Spec.Kind {
	case ProfileRecordingKindSelinuxProfile:
		if pr.Spec.Recorder != ProfileRecorderLogs {
			return fmt.Errorf(
				"recorder %q is not supported for %s, only %q is supported",
				pr.Spec.Recorder, pr.Spec.Kind, ProfileRecorderLogs,
			)
		}
	case ProfileRecordingKindAppArmorProfile:
		if pr.Spec.Recorder != ProfileRecorderBpf {
			return fmt.Errorf(
				"recorder %q is not supported for %s, only %q is supported",
				pr.Spec.Recorder, pr.Spec.Kind, ProfileRecorderBpf,
			)
		}
	case ProfileRecordingKindSeccompProfile:
		// All recorders are supported.
	default:
		return fmt.Errorf("unsupported kind: %s", pr.Spec.Kind)
	}

	return nil
}

func (pr *ProfileRecording) ctrAnnotationValue(ctrName string) string {
	const nonceSize = 5

	return fmt.Sprintf(
		"%s_%s_%s_%d",
		pr.GetName(),
		ctrName,
		utilrand.String(nonceSize),
		time.Now().Unix(),
	)
}

func (pr *ProfileRecording) ctrAnnotationSeccomp(ctrName string) (key, value string, err error) {
	var annotationPrefix string

	switch pr.Spec.Recorder {
	case ProfileRecorderLogs:
		annotationPrefix = config.SeccompProfileRecordLogsAnnotationKey
	case ProfileRecorderBpf:
		annotationPrefix = config.SeccompProfileRecordBpfAnnotationKey
	default:
		return "", "", fmt.Errorf(
			"invalid recorder: %s", pr.Spec.Recorder,
		)
	}

	key = annotationPrefix + ctrName
	value = pr.ctrAnnotationValue(ctrName)

	return key, value, err
}

func (pr *ProfileRecording) ctrAnnotationSelinux(ctrName string) (key, value string, err error) {
	var annotationPrefix string

	switch pr.Spec.Recorder {
	case ProfileRecorderLogs:
		annotationPrefix = config.SelinuxProfileRecordLogsAnnotationKey
	case ProfileRecorderBpf:
		return "", "", fmt.Errorf(
			"invalid recorder: %s, only %s is supported", pr.Spec.Recorder, ProfileRecorderLogs,
		)
	default:
		return "", "", fmt.Errorf(
			"invalid recorder: %s, only %s is supported", pr.Spec.Recorder, ProfileRecorderLogs,
		)
	}

	value = pr.ctrAnnotationValue(ctrName)
	key = annotationPrefix + ctrName

	return
}

func (pr *ProfileRecording) ctrAnnotationApparmor(ctrName string) (key, value string, err error) {
	var annotationPrefix string

	switch pr.Spec.Recorder {
	case ProfileRecorderBpf:
		annotationPrefix = config.ApparmorProfileRecordBpfAnnotationKey
	case ProfileRecorderLogs:
		return "", "", fmt.Errorf(
			"invalid recorder: %s, only %s is supported", pr.Spec.Recorder, ProfileRecorderBpf,
		)
	default:
		return "", "", fmt.Errorf(
			"invalid recorder: %s, only %s is supported", pr.Spec.Recorder, ProfileRecorderBpf,
		)
	}

	key = annotationPrefix + ctrName
	value = pr.ctrAnnotationValue(ctrName)

	return key, value, err
}

// +kubebuilder:object:root=true

// ProfileRecordingList contains a list of ProfileRecording.
type ProfileRecordingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProfileRecording `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(&ProfileRecording{}, &ProfileRecordingList{})
}
