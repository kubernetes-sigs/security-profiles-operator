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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ProfileBindingKind string

const (
	ProfileBindingKindSeccompProfile  ProfileBindingKind = "SeccompProfile"
	ProfileBindingKindSelinuxProfile  ProfileBindingKind = "SelinuxProfile"
	ProfileBindingKindAppArmorProfile ProfileBindingKind = "AppArmorProfile"
	SelectAllContainersImage          string             = "*"
)

// ProfileBindingSpec defines the desired state of ProfileBinding.
type ProfileBindingSpec struct {
	// profileRef references a SeccompProfile or other profile type in the current namespace.
	// +required
	ProfileRef ProfileRef `json:"profileRef,omitzero"`
	// image specifies the container image name within pod containers to match to the profile.
	// Use the "*" string to bind the profile to all pods.
	// +required
	// +kubebuilder:validation:MinLength=1
	Image string `json:"image,omitempty"`
}

// ProfileRef contains information that points to the profile being used.
type ProfileRef struct {
	// kind specifies the type of object to be bound.
	// +required
	// +kubebuilder:validation:Enum=SeccompProfile;SelinuxProfile;AppArmorProfile
	Kind ProfileBindingKind `json:"kind,omitempty"`
	// name is the name of the profile within the current namespace to which to bind the selected pods.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
}

// ProfileBindingStatus contains status of the Profilebinding.
type ProfileBindingStatus struct {
	// activeWorkloads lists the workloads currently using this binding.
	// +optional
	// +listType=set
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
}

// +kubebuilder:object:root=true

// ProfileBinding is the Schema for the profilebindings API.
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
type ProfileBinding struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the ProfileBinding.
	// +required
	Spec ProfileBindingSpec `json:"spec,omitzero"`
	// status contains the observed state of the ProfileBinding.
	// +optional
	Status ProfileBindingStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ProfileBindingList contains a list of ProfileBinding.
type ProfileBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProfileBinding `json:"items"`
}

func init() { //nolint:gochecknoinits // required to register the scheme
	SchemeBuilder.Register(&ProfileBinding{}, &ProfileBindingList{})
}
