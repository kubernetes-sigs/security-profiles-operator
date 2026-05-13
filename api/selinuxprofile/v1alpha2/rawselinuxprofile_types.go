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

package v1alpha2

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
)

var (
	// Ensure RawSelinuxProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
	_ profilebasev1alpha1.StatusBaseUser      = &RawSelinuxProfile{}
	_ profilebasev1alpha1.SecurityProfileBase = &RawSelinuxProfile{}
)

// RawSelinuxProfileSpec defines the desired state of RawSelinuxProfile.
type RawSelinuxProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1alpha1.SpecBase `json:",inline"`

	Policy string `json:"policy,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RawSelinuxProfile is the Schema for the rawselinuxprofiles API.
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=rawselinuxprofiles,scope=Cluster
// +kubebuilder:printcolumn:name="Usage",type="string",JSONPath=`.status.usage`
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.status`
type RawSelinuxProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RawSelinuxProfileSpec `json:"spec,omitempty"`
	Status SelinuxProfileStatus  `json:"status,omitempty"`
}

func (sp *RawSelinuxProfile) GetStatusBase() *profilebasev1alpha1.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *RawSelinuxProfile) DeepCopyToStatusBaseIf() profilebasev1alpha1.StatusBaseUser {
	return sp.DeepCopy()
}

func (sp *RawSelinuxProfile) SetImplementationStatus() {
	sp.Status.Usage = sp.GetPolicyUsage()
}

// GetPolicyName gets the policy module name in the format that
// we're expecting for parsing.
func (sp *RawSelinuxProfile) GetPolicyName() string {
	return sp.GetName()
}

// GetPolicyUsage is the representation of how a pod will call this
// SELinux module.
func (sp *RawSelinuxProfile) GetPolicyUsage() string {
	return sp.GetPolicyName() + ".process"
}

func (sp *RawSelinuxProfile) ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recording string,
) ([]metav1.Object, error) {
	return profilebasev1alpha1.ListProfilesByRecording(ctx, cli, recording, sp.Namespace, &RawSelinuxProfileList{})
}

func (sp *RawSelinuxProfile) IsPartial() bool {
	return profilebasev1alpha1.IsPartial(sp)
}

func (sp *RawSelinuxProfile) IsDisabled() bool {
	return profilebasev1alpha1.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *RawSelinuxProfile) IsReconcilable() bool {
	return profilebasev1alpha1.IsReconcilable(sp)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RawSelinuxProfileList contains a list of RawSelinuxProfile.
type RawSelinuxProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RawSelinuxProfile `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(&RawSelinuxProfile{}, &RawSelinuxProfileList{})
}
