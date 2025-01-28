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
	"sort"

	"github.com/containers/common/pkg/seccomp"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A ConditionType represents a condition a resource could be in.
type ConditionType string

// Condition types.
const (
	// TypeReady resources are believed to be ready to handle work.
	TypeReady ConditionType = "Ready"
)

// A ConditionReason represents the reason a resource is in a condition.
type ConditionReason string

// Reasons a resource is or is not ready.
const (
	ReasonAvailable   ConditionReason = "Available"
	ReasonUnavailable ConditionReason = "Unavailable"
	ReasonCreating    ConditionReason = "Creating"
	ReasonDeleting    ConditionReason = "Deleting"
	ReasonPending     ConditionReason = "Pending"
	ReasonUpdating    ConditionReason = "Updating"
)

// A Condition that may apply to a resource.
type Condition struct {
	// Type of this condition. At most one of each condition type may apply to
	// a resource at any point in time.
	Type ConditionType `json:"type"`

	// Status of this condition; is it currently True, False, or Unknown?
	Status corev1.ConditionStatus `json:"status"`

	// LastTransitionTime is the last time this condition transitioned from one
	// status to another.
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// A Reason for this condition's last transition from one status to another.
	Reason ConditionReason `json:"reason"`

	// A Message containing details about this condition's last transition from
	// one status to another, if any.
	// +optional
	Message string `json:"message,omitempty"`
}

// Equal returns true if the condition is identical to the supplied condition,
// ignoring the LastTransitionTime.
//
//nolint:gocritic // just a few bytes too heavy
func (c *Condition) Equal(other Condition) bool {
	return c.Type == other.Type &&
		c.Status == other.Status &&
		c.Reason == other.Reason &&
		c.Message == other.Message
}

// A ConditionedStatus reflects the observed status of a resource. Only one
// condition of each type may exist.
type ConditionedStatus struct {
	// Conditions of the resource.
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`
}

// GetCondition returns the condition for the given ConditionType if exists,
// otherwise returns an unknown condition.
func (s *ConditionedStatus) GetReadyCondition() Condition {
	for _, c := range s.Conditions {
		if c.Type == TypeReady {
			return c
		}
	}

	return Condition{
		Type:   TypeReady,
		Status: corev1.ConditionUnknown,
	}
}

// SetConditions sets the supplied conditions, replacing any existing conditions
// of the same type. This is a no-op if all supplied conditions are identical,
// ignoring the last transition time, to those already set.
func (s *ConditionedStatus) SetConditions(c ...Condition) {
	for _, new := range c {
		exists := false

		for i, existing := range s.Conditions {
			if existing.Type != new.Type {
				continue
			}

			if existing.Equal(new) {
				exists = true

				continue
			}

			s.Conditions[i] = new
			exists = true
		}

		if !exists {
			s.Conditions = append(s.Conditions, new)
		}
	}
}

// Equal returns true if the status is identical to the supplied status,
// ignoring the LastTransitionTimes and order of statuses.
func (s *ConditionedStatus) Equal(other *ConditionedStatus) bool {
	if s == nil || other == nil {
		return s == nil && other == nil
	}

	if len(other.Conditions) != len(s.Conditions) {
		return false
	}

	sc := make([]Condition, len(s.Conditions))
	copy(sc, s.Conditions)

	oc := make([]Condition, len(other.Conditions))
	copy(oc, other.Conditions)

	// We should not have more than one condition of each type.
	sort.Slice(sc, func(i, j int) bool { return sc[i].Type < sc[j].Type })
	sort.Slice(oc, func(i, j int) bool { return oc[i].Type < oc[j].Type })

	for i := range sc {
		if !sc[i].Equal(oc[i]) {
			return false
		}
	}

	return true
}

// Creating returns a condition that indicates the resource is currently
// being created.
func Creating() Condition {
	return Condition{
		Type:               TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonCreating,
	}
}

// Deleting returns a condition that indicates the resource is currently
// being deleted.
func Deleting() Condition {
	return Condition{
		Type:               TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonDeleting,
	}
}

// Available returns a condition that indicates the resource is
// currently observed to be available for use.
func Available() Condition {
	return Condition{
		Type:               TypeReady,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonAvailable,
	}
}

// Unavailable returns a condition that indicates the resource is not
// currently available for use. Unavailable should be set only when Crossplane
// expects the resource to be available but knows it is not, for example
// because its API reports it is unhealthy.
func Unavailable() Condition {
	return Condition{
		Type:               TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonUnavailable,
	}
}

// Pending returns a condition that indicates the resource is currently
// observed to be waiting for creating.
func Pending() Condition {
	return Condition{
		Type:               TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonPending,
	}
}

// Updating returns a condition that indicates the resource is currently
// observed to be updating.
func Updating() Condition {
	return Condition{
		Type:               TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             ReasonUpdating,
	}
}

// SelinuxOptions defines options specific to the SELinux
// functionality of the SecurityProfilesOperator.
type SelinuxOptions struct {
	// Lists the profiles coming from the system itself that are
	// allowed to be inherited by workloads. Use this with care,
	// as this might provide a lot of permissions depending on the
	// policy.
	// +kubebuilder:default={"container"}
	AllowedSystemProfiles []string `json:"allowedSystemProfiles,omitempty"`
}

type WebhookOptions struct {
	// Name specifies which webhook do we configure
	Name string `json:"name,omitempty"`
	// FailurePolicy sets the webhook failure policy
	// +optional
	FailurePolicy *admissionregv1.FailurePolicyType `json:"failurePolicy,omitempty"`
	// NamespaceSelector sets webhook's namespace selector
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// ObjectSelector sets webhook's object selector
	// +optional
	ObjectSelector *metav1.LabelSelector `json:"objectSelector,omitempty"`
}

// SPODStatus defines the desired state of SPOD.
type SPODSpec struct {
	// Verbosity specifies the logging verbosity of the daemon.
	Verbosity uint `json:"verbosity,omitempty"`
	// EnableProfiling tells the operator whether or not to enable profiling
	// support for this SPOD instance.
	EnableProfiling bool `json:"enableProfiling,omitempty"`
	// EnableMemoryOptimization enables memory optimization in the controller
	// running inside of SPOD instance and watching for pods in the cluster.
	// This will make the controller loading in the cache memory only the pods
	// labelled explicitly for profile recording with 'spo.x-k8s.io/enable-recording=true'.
	EnableMemoryOptimization bool `json:"enableMemoryOptimization,omitempty"`
	// tells the operator whether or not to enable SELinux support for this
	// SPOD instance.
	EnableSelinux *bool `json:"enableSelinux,omitempty"`
	// If specified, the SELinux type tag applied to the security context of SPOD.
	// +optional
	// +kubebuilder:default="spc_t"
	SelinuxTypeTag string `json:"selinuxTypeTag,omitempty"`
	// tells the operator whether or not to enable log enrichment support for this
	// SPOD instance.
	EnableLogEnricher bool `json:"enableLogEnricher,omitempty"`
	// tells the operator whether or not to enable bpf recorder support for this
	// SPOD instance.
	EnableBpfRecorder bool `json:"enableBpfRecorder,omitempty"`
	// tells the operator whether or not to enable AppArmor support for this
	// SPOD instance.
	EnableAppArmor bool `json:"enableAppArmor,omitempty"`
	// If specified, the SPOD's tolerations.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// Defines options specific to the SELinux
	// functionality of the SecurityProfilesOperator
	SelinuxOpts SelinuxOptions `json:"selinuxOptions,omitempty"`
	// HostProcVolumePath is the path for specifying a custom host /proc
	// volume, which is required for the log-enricher as well as bpf-recorder
	// to retrieve the container ID for a process ID. This can be helpful for
	// nested environments, for example when using "kind".
	HostProcVolumePath string `json:"hostProcVolumePath,omitempty"`
	// StaticWebhookConfig indicates whether the webhook configuration and its
	// related resources are statically deployed. In this case, the operator will
	// not create or update the webhook configuration and its related resources.
	// +optional
	StaticWebhookConfig bool `json:"staticWebhookConfig"`
	// WebhookOpts set custom namespace selectors and failure mode for
	// SPO's webhooks
	// +optional
	WebhookOpts []WebhookOptions `json:"webhookOptions,omitempty"`
	// AllowedSyscalls if specified, a list of system calls which are allowed
	// in seccomp profiles.
	// +optional
	AllowedSyscalls []string `json:"allowedSyscalls,omitempty"`
	// AllowedSeccompActions if specified, a list of allowed seccomp actions.
	// +optional
	AllowedSeccompActions []seccomp.Action `json:"allowedSeccompActions"`
	// Affinity if specified, the SPOD's affinity.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// ImagePullSecrets if defined, list of references to secrets in the security-profiles-operator's
	// namespace to use for pulling the images from SPOD pod from a private registry.
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// DaemonResourceRequirements if defined, overwrites the default resource requirements
	// of SPOD daemon.
	// +optional
	DaemonResourceRequirements *corev1.ResourceRequirements `json:"daemonResourceRequirements,omitempty"`

	// PriorityClassName if defined, indicates the spod pod priority class.
	// +optional
	// +kubebuilder:default="system-node-critical"
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// DisableOCIArtifactSignatureVerification can be used to disable OCI
	// artifact signature verification.
	// +optional
	DisableOCIArtifactSignatureVerification bool `json:"disableOciArtifactSignatureVerification"`
}

// SPODState defines the state that the spod is in.
type SPODState string

const (
	// The SPOD instance is pending installation.
	SPODStatePending SPODState = "PENDING"
	// The SPOD instance is being created.
	SPODStateCreating SPODState = "CREATING"
	// The SPOD instance is being updated.
	SPODStateUpdating SPODState = "UPDATING"
	// The SPOD instance was installed successfully.
	SPODStateRunning SPODState = "RUNNING"
	// The SPOD instance couldn't be installed.
	SPODStateError SPODState = "ERROR"
)

// SPODStatus defines the observed state of SPOD.
type SPODStatus struct {
	ConditionedStatus `json:",inline"`
	// Represents the state that the policy is in. Can be:
	// PENDING, IN-PROGRESS, RUNNING or ERROR
	State SPODState `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityProfilesOperatorDaemon is the Schema to configure the spod deployment.
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=securityprofilesoperatordaemons,shortName=spod
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.state`
type SecurityProfilesOperatorDaemon struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SPODSpec   `json:"spec,omitempty"`
	Status SPODStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityProfilesOperatorDaemonList contains a list of SecurityProfilesOperatorDaemon.
type SecurityProfilesOperatorDaemonList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityProfilesOperatorDaemon `json:"items"`
}

func (s *SPODStatus) StatePending() {
	s.State = SPODStatePending
	s.ConditionedStatus.SetConditions(Pending())
}

func (s *SPODStatus) StateCreating() {
	s.State = SPODStateCreating
	s.ConditionedStatus.SetConditions(Creating())
}

func (s *SPODStatus) StateUpdating() {
	s.State = SPODStateUpdating
	s.ConditionedStatus.SetConditions(Updating())
}

func (s *SPODStatus) StateRunning() {
	s.State = SPODStateRunning
	s.ConditionedStatus.SetConditions(Available())
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(&SecurityProfilesOperatorDaemon{}, &SecurityProfilesOperatorDaemonList{})
}
