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
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
)

// restrictedDirectives contains CIL statements that alter global node state
// or should not be allowed within a namespace-scoped container profile.
var restrictedDirectives = map[string]struct{}{
	"block":            {},
	"blockinherit":     {},
	"blockstart":       {},
	"booleanif":        {},
	"category":         {},
	"categoryorder":    {},
	"class":            {},
	"classmap":         {},
	"classmapping":     {},
	"classorder":       {},
	"context":          {},
	"dominance":        {},
	"filecon":          {},
	"genfscon":         {},
	"level":            {},
	"levelrange":       {},
	"mls":              {},
	"netifcon":         {},
	"nodecon":          {},
	"optional":         {},
	"policycap":        {},
	"portcon":          {},
	"role":             {},
	"roletype":         {},
	"sensitivity":      {},
	"sensitivityorder": {},
	"sid":              {},
	"sidcontext":       {},
	"sidorder":         {},
	"tunable":          {},
	"tunableif":        {},
	"typepermissive":   {},
	"user":             {},
	"userrole":         {},
}

var (
	// Ensure RawSelinuxProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
	_ profilebasev1.StatusBaseUser      = &RawSelinuxProfile{}
	_ profilebasev1.SecurityProfileBase = &RawSelinuxProfile{}
)

// RawSelinuxProfileSpec defines the desired state of RawSelinuxProfile.
type RawSelinuxProfileSpec struct {
	// Common spec fields for all profiles.
	profilebasev1.SpecBase `json:",inline"`

	// policy is the raw SELinux policy module content.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=500000
	Policy string `json:"policy,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RawSelinuxProfile is the Schema for the rawselinuxprofiles API.
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=rawselinuxprofiles,scope=Cluster
// +kubebuilder:printcolumn:name="Usage",type="string",JSONPath=`.status.usage`
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.status`
type RawSelinuxProfile struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the RawSelinuxProfile.
	// +optional
	Spec RawSelinuxProfileSpec `json:"spec,omitempty"`
	// status contains the observed state of the RawSelinuxProfile.
	// +optional
	Status SelinuxProfileStatus `json:"status,omitempty"`
}

func (sp *RawSelinuxProfile) GetStatusBase() *profilebasev1.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *RawSelinuxProfile) DeepCopyToStatusBaseIf() profilebasev1.StatusBaseUser {
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
	return profilebasev1.ListProfilesByRecording(ctx, cli, recording, sp.Namespace, &RawSelinuxProfileList{})
}

func (sp *RawSelinuxProfile) ValidatePolicy() error {
	policy := sp.Spec.Policy

	if strings.TrimSpace(policy) == "" {
		return errors.New("policy must not be empty")
	}

	if !utf8.ValidString(policy) {
		return errors.New("policy must be valid UTF-8")
	}

	if strings.ContainsRune(policy, '\x00') {
		return errors.New("policy must not contain null bytes")
	}

	// Prevent block escape via unbalanced parentheses.
	depth := 0
	directive := []rune{}
	directives := map[string]struct{}{}

	for _, r := range policy {
		switch r {
		case '(':
			depth++
			directive = []rune{}
		case ')':
			depth--
			if depth < 0 {
				return errors.New(
					"invalid policy: unmatched closing parenthesis ')' allows block escape")
			}
		default:
			if isDirectiveCharacter(r) {
				directive = append(directive, r)
			} else {
				if len(directive) > 0 {
					directives[string(directive)] = struct{}{}
					directive = []rune{}
				}
			}
		}
	}

	if depth != 0 {
		return errors.New("invalid policy: unbalanced parentheses")
	}

	// Prevent Global Privilege Escalation: Reject dangerous CIL directives.
	// Check out all found directives in the policy and see if any of them are
	// in the restricted list.
	for directive := range directives {
		if _, ok := restrictedDirectives[strings.ToLower(directive)]; ok {
			return fmt.Errorf(
				"invalid policy: use of restricted global directive '%s' is not allowed",
				directive)
		}
	}

	return nil
}

func isDirectiveCharacter(r rune) bool {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return true
	}
	switch r {
	case '_', '-':
		return true
	default:
		return false
	}
}

func (sp *RawSelinuxProfile) IsPartial() bool {
	return profilebasev1.IsPartial(sp)
}

func (sp *RawSelinuxProfile) IsDisabled() bool {
	return profilebasev1.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *RawSelinuxProfile) IsReconcilable() bool {
	return profilebasev1.IsReconcilable(sp)
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
