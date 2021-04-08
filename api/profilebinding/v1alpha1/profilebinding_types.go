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

// ProfileBindingSpec defines the desired state of ProfileBinding.
type ProfileBindingSpec struct {
	// ProfileRef references a SeccompProfile or other profile type in the current namespace.
	ProfileRef ProfileRef `json:"profileRef"`
	// Image name within pod containers to match to the profile.
	Image string `json:"image"`
}

// ProfileRef contains information that points to the profile being used.
type ProfileRef struct {
	// Kind of object to be bound.
	// +kubebuilder:validation:Enum=SeccompProfile
	Kind string `json:"kind"` // TODO(cmurphy) add SelinuxProfile
	// Name of the profile within the current namespace to which to bind the selected pods.
	Name string `json:"name"`
}

// ProfileBindingStatus contains status of the Profilebinding.
type ProfileBindingStatus struct {
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
}

// +kubebuilder:object:root=true

// ProfileBinding is the Schema for the profilebindings API.
// +kubebuilder:subresource:status
type ProfileBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProfileBindingSpec   `json:"spec,omitempty"`
	Status ProfileBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProfileBindingList contains a list of ProfileBinding.
type ProfileBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProfileBinding `json:"items"`
}

func init() { //nolint:gochecknoinits
	SchemeBuilder.Register(&ProfileBinding{}, &ProfileBindingList{})
}
