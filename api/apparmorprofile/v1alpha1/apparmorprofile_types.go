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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
)

const (
	profilePrefix string = "spo-"
)

// Ensure AppArmorProfile implements the StatusBaseUser interface.
var _ profilebasev1alpha1.StatusBaseUser = &AppArmorProfile{}

// AppArmorProfileSpec defines the desired state of AppArmorProfile.
type AppArmorProfileSpec struct {
	Policy string `json:"policy,omitempty"`
}

// AppArmorProfileStatus defines the observed state of AppArmorProfile.
type AppArmorProfileStatus struct {
	profilebasev1alpha1.StatusBase `json:",inline"`
}

// +kubebuilder:object:root=true

// AppArmorProfile is a cluster level specification for an AppArmor profile.
// +kubebuilder:resource:shortName=aa
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.status`
type AppArmorProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AppArmorProfileSpec   `json:"spec,omitempty"`
	Status AppArmorProfileStatus `json:"status,omitempty"`
}

func (sp *AppArmorProfile) GetStatusBase() *profilebasev1alpha1.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *AppArmorProfile) DeepCopyToStatusBaseIf() profilebasev1alpha1.StatusBaseUser {
	return sp.DeepCopy()
}

func (sp *AppArmorProfile) SetImplementationStatus() {
}

// +kubebuilder:object:root=true

// AppArmorProfileList contains a list of AppArmorProfile.
type AppArmorProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AppArmorProfile `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(&AppArmorProfile{}, &AppArmorProfileList{})
}

func (sp *AppArmorProfile) GetProfileName() string {
	return profilePrefix + sp.GetName()
}
