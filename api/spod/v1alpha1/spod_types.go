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
	"github.com/containers/common/pkg/seccomp"
	rcommonv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
}

// SPODStatus defines the desired state of SPOD.
type SPODSpec struct {
	// Verbosity specifies the logging verbosity of the daemon.
	Verbosity uint `json:"verbosity,omitempty"`
	// EnableProfiling tells the operator whether or not to enable profiling
	// support for this SPOD instance.
	EnableProfiling bool `json:"enableProfiling,omitempty"`
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
	// tells the operator whether or not to apply labels to pods that present
	// security policy-related denials. Note that this will be done cluster-wide.
	// Note that this currently requires the log enricher to be enabled.
	LabelPodDenials bool `json:"labelPodDenials,omitempty"`
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
	StaticWebhookConfig bool `json:"manualWebhookConfig"`

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
	rcommonv1.ConditionedStatus `json:",inline"`
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
	s.ConditionedStatus.SetConditions(rcommonv1.Condition{
		Type:               rcommonv1.TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             "Pending",
	})
}

func (s *SPODStatus) StateCreating() {
	s.State = SPODStateCreating
	s.ConditionedStatus.SetConditions(rcommonv1.Creating())
}

func (s *SPODStatus) StateUpdating() {
	s.State = SPODStateUpdating
	s.ConditionedStatus.SetConditions(rcommonv1.Condition{
		Type:               rcommonv1.TypeReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             "Updating",
	})
}

func (s *SPODStatus) StateRunning() {
	s.State = SPODStateRunning
	s.ConditionedStatus.SetConditions(rcommonv1.Available())
}

func init() { // nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(&SecurityProfilesOperatorDaemon{}, &SecurityProfilesOperatorDaemonList{})
}
