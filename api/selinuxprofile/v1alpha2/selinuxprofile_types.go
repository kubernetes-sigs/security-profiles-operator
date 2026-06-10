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
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// AllowSelf describes an "allow" entry meant to give
	// the same process.
	AllowSelf = "@self"
)

// Ensure SelinuxProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
var (
	_ profilebasev1alpha1.StatusBaseUser      = &SelinuxProfile{}
	_ profilebasev1alpha1.SecurityProfileBase = &SelinuxProfile{}
)

type PolicyRef struct {
	// kind specifies the type of policy that this inherits from.
	// Can be a SelinuxProfile object or "System" if an already
	// installed policy will be used.
	// The allowed "System" policies are available in the
	// SecurityProfilesOperatorDaemon instance.
	// +optional
	// +default="System"
	// +kubebuilder:validation:Enum=System;SelinuxProfile;
	Kind string `json:"kind,omitempty"`
	// name is the name of the policy that this inherits from.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
}

// SelinuxMode describes the enforcement mode for a SELinux profile.
// +kubebuilder:validation:Enum=Enforcing;Permissive
type SelinuxMode string

const (
	SelinuxModeEnforcing  SelinuxMode = "Enforcing"
	SelinuxModePermissive SelinuxMode = "Permissive"
)

// SelinuxProfileSpec defines the desired state of SelinuxProfile.
type SelinuxProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1alpha1.SpecBase `json:",inline"`

	// inherit specifies a SELinuxProfile or set of profiles that this inherits from.
	// Note that they need to be in the same namespace.
	// +optional
	// +default=[{"kind":"System","name":"container"}]
	// +listType=atomic
	Inherit []PolicyRef `json:"inherit,omitempty"`
	// mode controls the enforcement mode for the SELinux profile.
	// In "Permissive" mode, violations are logged but allowed.
	// In "Enforcing" mode (the default), violations are denied.
	// +optional
	// +default="Enforcing"
	Mode SelinuxMode `json:"mode,omitempty"`
	// allow defines the allow policy for the profile.
	// +optional
	Allow Allow `json:"allow,omitempty"`
}

type LabelKey string

func (lk LabelKey) String() string {
	return string(lk)
}

type ObjectClassKey string

func (ock ObjectClassKey) String() string {
	return string(ock)
}

type PermissionSet []string

// Allow defines the allow policy for the profile.
type Allow map[LabelKey]map[ObjectClassKey]PermissionSet

func SortLabelKeys(allow Allow) []LabelKey {
	keys := util.MapKeys(allow)
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].String() < keys[j].String()
	})

	return keys
}

func SortObjectClassKeys(ock map[ObjectClassKey]PermissionSet) []ObjectClassKey {
	keys := util.MapKeys(ock)
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].String() < keys[j].String()
	})

	return keys
}

// SelinuxProfileStatus defines the observed state of SelinuxProfile.
type SelinuxProfileStatus struct {
	// Common status fields for all profiles.
	profilebasev1alpha1.StatusBase `json:",inline"`

	// usage represents the string that the SelinuxProfile object can be
	// referenced as in a pod seLinuxOptions section.
	// +optional
	Usage string `json:"usage,omitempty"`
	// activeWorkloads lists the workloads currently using this profile.
	// +optional
	// +listType=set
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SelinuxProfile is the Schema for the selinuxprofiles API.
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=selinuxprofiles,scope=Cluster
// +kubebuilder:printcolumn:name="Usage",type="string",JSONPath=`.status.usage`
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.status`
type SelinuxProfile struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the SelinuxProfile.
	// +optional
	Spec SelinuxProfileSpec `json:"spec,omitempty"`
	// status contains the observed state of the SelinuxProfile.
	// +optional
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
	return sp.GetName()
}

// GetPolicyUsage is the representation of how a pod will call this
// SELinux module.
func (sp *SelinuxProfile) GetPolicyUsage() string {
	return sp.GetPolicyName() + ".process"
}

func (sp *SelinuxProfile) ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recording string,
) ([]metav1.Object, error) {
	return profilebasev1alpha1.ListProfilesByRecording(ctx, cli, recording, sp.Namespace, &SelinuxProfileList{})
}

func (sp *SelinuxProfile) IsPartial() bool {
	return profilebasev1alpha1.IsPartial(sp)
}

func (sp *SelinuxProfile) IsDisabled() bool {
	return profilebasev1alpha1.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *SelinuxProfile) IsReconcilable() bool {
	return profilebasev1alpha1.IsReconcilable(sp)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SelinuxProfileList contains a list of SelinuxProfile.
type SelinuxProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SelinuxProfile `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init scheme
	SchemeBuilder.Register(&SelinuxProfile{}, &SelinuxProfileList{})
}
