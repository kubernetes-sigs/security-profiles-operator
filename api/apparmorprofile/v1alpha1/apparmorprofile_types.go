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
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
)

var (
	// Ensure AppArmorProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
	_ profilebasev1alpha1.StatusBaseUser      = &AppArmorProfile{}
	_ profilebasev1alpha1.SecurityProfileBase = &AppArmorProfile{}
)

type AppArmorExecutablesRules struct {
	AllowedExecutables *[]string `json:"allowedExecutables,omitempty"`
	AllowedLibraries   *[]string `json:"allowedLibraries,omitempty"`
}

type AppArmorFsRules struct {
	ReadOnlyPaths  *[]string `json:"readOnlyPaths,omitempty"`
	WriteOnlyPaths *[]string `json:"writeOnlyPaths,omitempty"`
	ReadWritePaths *[]string `json:"readWritePaths,omitempty"`
}

type AppArmorAllowedProtocols struct {
	AllowTCP *bool `json:"allowTCP,omitempty"`
	AllowUDP *bool `json:"allowUDP,omitempty"`
}

type AppArmorNetworkRules struct {
	AllowRaw  *bool                     `json:"allowRaw,omitempty"`
	Protocols *AppArmorAllowedProtocols `json:"allowedProtocols,omitempty"`
}

type AppArmorCapabilityRules struct {
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}

type AppArmorAbstract struct {
	Executable *AppArmorExecutablesRules `json:"executable,omitempty"`
	Filesystem *AppArmorFsRules          `json:"filesystem,omitempty"`
	Network    *AppArmorNetworkRules     `json:"network,omitempty"`
	Capability *AppArmorCapabilityRules  `json:"capability,omitempty"`
}

// AppArmorProfileSpec defines the desired state of AppArmorProfile.
type AppArmorProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1alpha1.SpecBase `json:",inline"`

	Policy   string           `json:"policy,omitempty"`
	Abstract AppArmorAbstract `json:"abstract,omitempty"`
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

func (sp *AppArmorProfile) ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recording string,
) ([]metav1.Object, error) {
	return profilebasev1alpha1.ListProfilesByRecording(ctx, cli, recording, sp.Namespace, &AppArmorProfileList{})
}

func (sp *AppArmorProfile) IsPartial() bool {
	return profilebasev1alpha1.IsPartial(sp)
}

func (sp *AppArmorProfile) IsDisabled() bool {
	return profilebasev1alpha1.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *AppArmorProfile) IsReconcilable() bool {
	return profilebasev1alpha1.IsReconcilable(sp)
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
	return sp.GetName()
}
