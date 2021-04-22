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

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
)

// Ensure SelinuxProfile implements the StatusBaseUser interface.
var _ profilebasev1alpha1.StatusBaseUser = &SelinuxProfile{}

// SelinuxProfileSpec defines the desired state of SelinuxProfile.
type SelinuxProfileSpec struct {
	Policy string `json:"policy,omitempty"`
}

// SelinuxProfileStatus defines the observed state of SelinuxProfile.
type SelinuxProfileStatus struct {
	profilebasev1alpha1.StatusBase `json:",inline"`
	// Represents the string that the SelinuxProfile object can be
	// referenced as in a pod seLinuxOptions section.
	Usage string `json:"usage,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SelinuxProfile is the Schema for the selinuxprofiles API.
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=selinuxprofiles,scope=Namespaced
// +kubebuilder:printcolumn:name="Usage",type="string",JSONPath=`.status.usage`
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.status`
type SelinuxProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SelinuxProfileSpec   `json:"spec,omitempty"`
	Status SelinuxProfileStatus `json:"status,omitempty"`
}

func (sp *SelinuxProfile) GetStatusBase() *profilebasev1alpha1.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *SelinuxProfile) DeepCopyToStatusBaseIf() profilebasev1alpha1.StatusBaseUser {
	return sp.DeepCopy()
}

func (sp *SelinuxProfile) SetImplementationStatus() {
	sp.Status.Usage = sp.GetPolicyUsage()
}

// GetPolicyName gets the policy module name in the format that
// we're expecting for parsing.
func (sp *SelinuxProfile) GetPolicyName() string {
	return sp.GetName() + "_" + sp.GetNamespace()
}

// GetPolicyUsage is the representation of how a pod will call this
// SELinux module.
func (sp *SelinuxProfile) GetPolicyUsage() string {
	return sp.GetPolicyName() + ".process"
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SelinuxProfileList contains a list of SelinuxProfile.
type SelinuxProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SelinuxProfile `json:"items"`
}

func init() { //nolint:gochecknoinits
	SchemeBuilder.Register(&SelinuxProfile{}, &SelinuxProfileList{})
}
