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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ProfileRecordingKind string

const (
	ProfileRecordingKindSeccompProfile ProfileRecordingKind = "SeccompProfile"
)

type ProfileRecorder string

const (
	ProfileRecorderHook ProfileRecorder = "hook"
	ProfileRecorderLogs ProfileRecorder = "logs"
)

// ProfileRecordingSpec defines the desired state of ProfileRecording.
type ProfileRecordingSpec struct {
	// Kind of object to be recorded.
	// +kubebuilder:validation:Enum=SeccompProfile
	Kind ProfileRecordingKind `json:"kind"`

	// Recorder to be used.
	// +kubebuilder:validation:Enum=hook;logs
	Recorder ProfileRecorder `json:"recorder"`

	// PodSelector selects the pods to record. This field follows standard
	// label selector semantics. An empty podSelector matches all pods in this
	// namespace.
	PodSelector metav1.LabelSelector `json:"podSelector"`
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

// +kubebuilder:object:root=true

// ProfileRecordingList contains a list of ProfileRecording.
type ProfileRecordingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProfileRecording `json:"items"`
}

func init() { //nolint:gochecknoinits
	SchemeBuilder.Register(&ProfileRecording{}, &ProfileRecordingList{})
}
