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

package v1

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

var (
	// Ensure AppArmorProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
	_ profilebasev1.StatusBaseUser      = &AppArmorProfile{}
	_ profilebasev1.SecurityProfileBase = &AppArmorProfile{}
)

// AppArmorExecutablesRules stores the rules for allowed executable.
type AppArmorExecutablesRules struct {
	// allowedExecutables is a list of allowed executables.
	// +optional
	// +listType=set
	AllowedExecutables []string `json:"allowedExecutables,omitempty"`
	// allowedLibraries is a list of allowed libraries.
	// +optional
	// +listType=set
	AllowedLibraries []string `json:"allowedLibraries,omitempty"`
}

// AppArmorFsRules stores the rules for file system access.
type AppArmorFsRules struct {
	// readOnlyPaths is a list of allowed read only file paths.
	// +optional
	// +listType=set
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`
	// writeOnlyPaths is a list of allowed write only file paths.
	// +optional
	// +listType=set
	WriteOnlyPaths []string `json:"writeOnlyPaths,omitempty"`
	// readWritePaths is a list of allowed read write file paths.
	// +optional
	// +listType=set
	ReadWritePaths []string `json:"readWritePaths,omitempty"`
}

// AppArmorAllowedProtocols stores the rules for allowed networking protocols.
type AppArmorAllowedProtocols struct {
	// allowTcp allows TCP socket connections.
	// +optional
	AllowTCP *bool `json:"allowTcp,omitempty"`
	// allowUdp allows UDP sockets connections.
	// +optional
	AllowUDP *bool `json:"allowUdp,omitempty"`
}

// AppArmorNetworkRules stores the rules for network access.
type AppArmorNetworkRules struct {
	// allowRaw allows raw sockets.
	// +optional
	AllowRaw *bool `json:"allowRaw,omitempty"`
	// allowedProtocols keeps the allowed networking protocols.
	// +optional
	Protocols *AppArmorAllowedProtocols `json:"allowedProtocols,omitempty"`
}

// AppArmorCapabilityRules stores the rules of allowed Linux capabilities.
type AppArmorCapabilityRules struct {
	// allowedCapabilities is a list of allowed capabilities.
	// +optional
	// +listType=set
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}

// AppArmorAbstract AppArmor profile which stores various allowed list for
// executable, file, network, capabilities access.
type AppArmorAbstract struct {
	// executable defines rules for allowed executables.
	// +optional
	Executable *AppArmorExecutablesRules `json:"executable,omitempty"`
	// filesystem defines rules for filesystem access.
	// +optional
	Filesystem *AppArmorFsRules `json:"filesystem,omitempty"`
	// network defines rules for network access.
	// +optional
	Network *AppArmorNetworkRules `json:"network,omitempty"`
	// capability defines rules for Linux capabilities.
	// +optional
	Capability *AppArmorCapabilityRules `json:"capability,omitempty"`
}

// AppArmorMode describes the enforcement mode for an AppArmor profile.
// +kubebuilder:validation:Enum=Enforce;Complain
type AppArmorMode string

const (
	AppArmorModeEnforce  AppArmorMode = "Enforce"
	AppArmorModeComplain AppArmorMode = "Complain"
)

// AppArmorProfileSpec defines the desired state of AppArmorProfile.
type AppArmorProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1.SpecBase `json:",inline"`

	// abstract stores the apparmor profile allow lists for executable, file, network and capabilities access.
	// +optional
	Abstract AppArmorAbstract `json:"abstract,omitempty"`

	// mode controls the enforcement mode for the AppArmor profile.
	// In "Complain" mode, violations are logged but allowed.
	// In "Enforce" mode (the default), violations are denied.
	// +optional
	// +default="Enforce"
	Mode AppArmorMode `json:"mode,omitempty"`
}

// AppArmorProfileStatus defines the observed state of AppArmorProfile.
type AppArmorProfileStatus struct {
	profilebasev1.StatusBase `json:",inline"`
}

// +kubebuilder:object:root=true

// AppArmorProfile is a cluster level specification for an AppArmor profile.
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=aa,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.status`
type AppArmorProfile struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the AppArmor profile.
	// +optional
	Spec AppArmorProfileSpec `json:"spec,omitempty"`
	// status contains the observed state of the AppArmor profile.
	// +optional
	Status AppArmorProfileStatus `json:"status,omitempty"`
}

func (sp *AppArmorProfile) GetStatusBase() *profilebasev1.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *AppArmorProfile) DeepCopyToStatusBaseIf() profilebasev1.StatusBaseUser {
	return sp.DeepCopy()
}

func (sp *AppArmorProfile) SetImplementationStatus() {
}

func (sp *AppArmorProfile) ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recording string,
) ([]metav1.Object, error) {
	return profilebasev1.ListProfilesByRecording(ctx, cli, recording, sp.Namespace, &AppArmorProfileList{})
}

func (sp *AppArmorProfile) IsPartial() bool {
	return profilebasev1.IsPartial(sp)
}

func (sp *AppArmorProfile) IsDisabled() bool {
	return profilebasev1.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *AppArmorProfile) IsReconcilable() bool {
	return profilebasev1.IsReconcilable(sp)
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
