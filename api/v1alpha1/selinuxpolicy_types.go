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

// SelinuxPolicySpec defines the desired state of SelinuxPolicy.
type SelinuxPolicySpec struct {
	Apply  bool   `json:"apply,omitempty"`
	Policy string `json:"policy,omitempty"`
}

// PolicyState defines the state that the policy is in.
type PolicyState string

const (
	// The policy is pending installation.
	PolicyStatePending PolicyState = "PENDING"
	// The policy is being installed.
	PolicyStateInProgress PolicyState = "IN-PROGRESS"
	// The policy was installed successfully.
	PolicyStateInstalled PolicyState = "INSTALLED"
	// The policy couldn't be installed.
	PolicyStateError PolicyState = "ERROR"
)

// SelinuxPolicyStatus defines the observed state of SelinuxPolicy.
type SelinuxPolicyStatus struct {
	// Represents the string that the SelinuxPolicy object can be
	// referenced as in a pod seLinuxOptions section.
	Usage string `json:"usage,omitempty"`
	// Represents the state that the policy is in. Can be:
	// PENDING, IN-PROGRESS, INSTALLED or ERROR
	State PolicyState `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SelinuxPolicy is the Schema for the selinuxpolicies API.
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=selinuxpolicies,scope=Namespaced
// +kubebuilder:printcolumn:name="Usage",type="string",JSONPath=`.status.usage`
// +kubebuilder:printcolumn:name="Apply",type="boolean",JSONPath=`.spec.apply`
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.state`
type SelinuxPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SelinuxPolicySpec   `json:"spec,omitempty"`
	Status SelinuxPolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SelinuxPolicyList contains a list of SelinuxPolicy.
type SelinuxPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SelinuxPolicy `json:"items"`
}

func init() { //nolint:gochecknoinits
	SchemeBuilder.Register(&SelinuxPolicy{}, &SelinuxPolicyList{})
}
