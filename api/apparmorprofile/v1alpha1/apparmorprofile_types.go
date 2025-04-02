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

// AppArmorExecutablesRules stores the rules for allowed executable.
type AppArmorExecutablesRules struct {
	// AllowedExecutables list of allowed executables.
	AllowedExecutables *[]string `json:"allowedExecutables,omitempty"`
	// AllowedLibraries list of allowed libraries.
	AllowedLibraries *[]string `json:"allowedLibraries,omitempty"`
}

// AppArmorFsRules stores the rules for file system access.
type AppArmorFsRules struct {
	// ReadOnlyPaths list of allowed read only file paths.
	ReadOnlyPaths *[]string `json:"readOnlyPaths,omitempty"`
	// WriteOnlyPaths list of allowed write only file paths.
	WriteOnlyPaths *[]string `json:"writeOnlyPaths,omitempty"`
	// ReadWritePaths list of allowed read write file paths.
	ReadWritePaths *[]string `json:"readWritePaths,omitempty"`
}

// AppArmorAllowedProtocols stores the rules for allowed networking protocols.
type AppArmorAllowedProtocols struct {
	// AllowTCP allows TCP socket connections.
	AllowTCP *bool `json:"allowTcp,omitempty"`
	// AllowUDP allows UDP sockets connections.
	AllowUDP *bool `json:"allowUdp,omitempty"`
}

// AppArmorNetworkRules stores the rules for network access.
type AppArmorNetworkRules struct {
	// AllowRaw allows raw sockets.
	AllowRaw *bool `json:"allowRaw,omitempty"`
	// Protocols keeps the allowed networking protocols.
	Protocols *AppArmorAllowedProtocols `json:"allowedProtocols,omitempty"`
}

// AllowedCapabilities stores the rules of allowed Linux capabilities.
type AppArmorCapabilityRules struct {
	// AllowedCapabilities lost of allowed capabilities.
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}

// AppArmorAbstract AppArmor profile which stores various allowed list for
// executable, file, network, capabilities access.
type AppArmorAbstract struct {
	// Executable rules for allowed executables.
	Executable *AppArmorExecutablesRules `json:"executable,omitempty"`
	// Filesystem rules for filesystem access.
	Filesystem *AppArmorFsRules `json:"filesystem,omitempty"`
	// Network rules for network access.
	Network *AppArmorNetworkRules `json:"network,omitempty"`
	// Capability rules for Linux capabilities.
	Capability *AppArmorCapabilityRules `json:"capability,omitempty"`
	// Extra rules for other config.
	Extra string `json:"extra,omitempty"`
}

// AppArmorProfileSpec defines the desired state of AppArmorProfile.
type AppArmorProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1alpha1.SpecBase `json:",inline"`

	// Abstract stores the apparmor profile allow lists for executable, file, network and capabilities access.
	Abstract AppArmorAbstract `json:"abstract,omitempty"`

	// ComplainMode places the apparmor profile into "complain" mode, by default is placed in "enforce" mode.
	// In complain mode, if a given action is not allowed, it will be allowed, but this violation will be
	// logged with a tag of access being "ALLOWED unconfined".
	ComplainMode bool `json:"complainMode,omitempty"`
}

// AppArmorProfileStatus defines the observed state of AppArmorProfile.
type AppArmorProfileStatus struct {
	profilebasev1alpha1.StatusBase `json:",inline"`
}

// +kubebuilder:object:root=true

// AppArmorProfile is a cluster level specification for an AppArmor profile.
// +kubebuilder:resource:shortName=aa,scope=Cluster
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
