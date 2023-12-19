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

package v1alpha1

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

type ProfileRecordingKind string

const (
	ProfileRecordingKindSeccompProfile ProfileRecordingKind = "SeccompProfile"
	ProfileRecordingKindSelinuxProfile ProfileRecordingKind = "SelinuxProfile"
)

type ProfileRecorder string

const (
	ProfileRecorderLogs ProfileRecorder = "logs"
	ProfileRecorderBpf  ProfileRecorder = "bpf"
)

type ProfileMergeStrategy string

const (
	ProfileMergeNone       ProfileMergeStrategy = "none"
	ProfileMergeContainers ProfileMergeStrategy = "containers"
)

const (
	// ProfileToRecordingLabel is the name of the ProfileRecording CR that produced this profile.
	ProfileToRecordingLabel = "spo.x-k8s.io/recording-id"
	// ProfileToContainerLabel is the name of the container that produced this profile.
	ProfileToContainerLabel = "spo.x-k8s.io/container-id"
	// RecordingHasUnmergedProfiles is a finalizer that indicates that the recording has partial policies. Its
	// main use is to hold off the deletion of the recording until all partial profiles are merged.
	RecordingHasUnmergedProfiles = "spo.x-k8s.io/has-unmerged-profiles"
)

// ProfileRecordingSpec defines the desired state of ProfileRecording.
type ProfileRecordingSpec struct {
	// Kind of object to be recorded.
	// +kubebuilder:validation:Enum=SeccompProfile;SelinuxProfile
	Kind ProfileRecordingKind `json:"kind"`

	// Recorder to be used.
	// +kubebuilder:validation:Enum=bpf;logs
	Recorder ProfileRecorder `json:"recorder"`

	// Whether or how to merge recorded profiles. Can be one of "none" or "containers".
	// Default is "none".
	// +optional
	// +kubebuilder:default="none"
	// +kubebuilder:validation:Enum=none;containers
	MergeStrategy ProfileMergeStrategy `json:"mergeStrategy"`

	// PodSelector selects the pods to record. This field follows standard
	// label selector semantics. An empty podSelector matches all pods in this
	// namespace.
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// Containers is a set of containers to record. This allows to select
	// only specific containers to record instead of all containers present
	// in the pod.
	// +optional
	Containers []string `json:"containers,omitempty"`

	// DisableProfileAfterRecording indicates whether the profile should be disabled
	// after recording and thus skipped during reconcile. In case of SELinux profiles,
	// reconcile can take a significant amount of time and for all profiles might not be needed.
	// This Defaults to false.
	// +optional
	// +kubebuilder:default=false
	DisableProfileAfterRecording bool `json:"disableProfileAfterRecording,omitempty"`
}

// ProfileRecordingStatus contains status of the ProfileRecording.
type ProfileRecordingStatus struct {
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
}

// +kubebuilder:object:root=true

// ProfileRecording is the Schema for the profilerecordings API.
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="PodSelector",type=string,priority=10,JSONPath=`.spec.podSelector`
type ProfileRecording struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProfileRecordingSpec   `json:"spec,omitempty"`
	Status ProfileRecordingStatus `json:"status,omitempty"`
}

func (pr *ProfileRecording) CtrAnnotation(ctrName string) (key, value string, err error) {
	switch pr.Spec.Kind {
	case ProfileRecordingKindSeccompProfile:
		return pr.ctrAnnotationSeccomp(ctrName)
	case ProfileRecordingKindSelinuxProfile:
		return pr.ctrAnnotationSelinux(ctrName)
	}

	return "", "", fmt.Errorf(
		"invalid kind: %s", pr.Spec.Kind,
	)
}

func (pr *ProfileRecording) IsKindSupported() bool {
	switch pr.Spec.Kind {
	case ProfileRecordingKindSelinuxProfile, ProfileRecordingKindSeccompProfile:
		return true
	}
	return false
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
	default:
		return "", "", fmt.Errorf(
			"invalid recorder: %s, only %s is supported", pr.Spec.Recorder, ProfileRecorderLogs,
		)
	}

	value = pr.ctrAnnotationValue(ctrName)
	key = annotationPrefix + ctrName
	return
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
