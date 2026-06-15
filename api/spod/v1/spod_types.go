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
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/api/common"
	seccompapi "sigs.k8s.io/security-profiles-operator/api/seccomp"
)

// SelinuxOptions defines options specific to the SELinux
// functionality of the SecurityProfilesOperator.
type SelinuxOptions struct {
	// allowedSystemProfiles lists the profiles coming from the system itself
	// that are allowed to be inherited by workloads. Use this with care,
	// as this might provide a lot of permissions depending on the policy.
	// +optional
	// +default=["container"]
	// +listType=set
	AllowedSystemProfiles []string `json:"allowedSystemProfiles,omitempty"`
}

// JsonEnricherOptions defines options specific to the JSON enricher.
type JsonEnricherOptions struct {
	// auditLogIntervalSeconds specifies the interval, in seconds, at which
	// the accumulated audit log data is output in JSON format. For each
	// process, syscalls occurring within this interval are grouped together.
	// The default is 60 seconds. Increasing this interval will reduce the
	// rate at which logs are written.
	// +optional
	// +kubebuilder:validation:Minimum=1
	AuditLogIntervalSeconds *int32 `json:"auditLogIntervalSeconds,omitempty"`
	// auditLogPath specifies the path for the accumulated audit log data.
	// The audit log will be written to this file in JSON format if a file
	// path is provided. If left unspecified, the output will be directed
	// to standard output (stdout).
	// +optional
	AuditLogPath *string `json:"auditLogPath,omitempty"`
	// auditLogMaxSize specifies the maximum size in megabytes of the audit
	// log file before it gets rotated. If left unspecified it defaults to
	// 100 MB.
	// +optional
	// +kubebuilder:validation:Minimum=1
	AuditLogMaxSize *int32 `json:"auditLogMaxSize,omitempty"`
	// auditLogMaxBackups specifies the maximum number of old audit log
	// files to retain. The default is to retain all old log files (though
	// MaxAge may still cause them to get deleted).
	// +optional
	// +kubebuilder:validation:Minimum=0
	AuditLogMaxBackups *int32 `json:"auditLogMaxBackups,omitempty"`
	// auditLogMaxAge specifies the maximum number of days to retain old
	// audit log files. The default is not to remove old log files based
	// on age.
	// +optional
	// +kubebuilder:validation:Minimum=0
	AuditLogMaxAge *int32 `json:"auditLogMaxAge,omitempty"`
}

// WebhookOptions defines per-webhook configuration options.
type WebhookOptions struct {
	// name specifies which webhook to configure.
	// +required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
	// failurePolicy sets the webhook failure policy.
	// +optional
	FailurePolicy *admissionregv1.FailurePolicyType `json:"failurePolicy,omitempty"`
	// namespaceSelector sets the webhook's namespace selector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// objectSelector sets the webhook's object selector.
	// +optional
	ObjectSelector *metav1.LabelSelector `json:"objectSelector,omitempty"`
}

// LogEnricherSource determines the source for audit log enrichment.
// +kubebuilder:validation:Enum=Auditd;Bpf
type LogEnricherSource string

const (
	LogEnricherSourceAuditd LogEnricherSource = "Auditd"
	LogEnricherSourceBpf    LogEnricherSource = "Bpf"
)

// SPODSpec defines the desired state of SPOD.
type SPODSpec struct {
	// verbosity specifies the logging verbosity of the daemon.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Verbosity int32 `json:"verbosity,omitempty"`
	// enableProfiling tells the operator whether or not to enable profiling
	// support for this SPOD instance.
	// +optional
	// +default=false
	EnableProfiling *bool `json:"enableProfiling,omitempty"`
	// enableMemoryOptimization enables memory optimization in the controller
	// running inside of SPOD instance and watching for pods in the cluster.
	// This will make the controller loading in the cache memory only the pods
	// labelled explicitly for profile recording with
	// 'spo.x-k8s.io/enable-recording=true'.
	// +optional
	// +default=false
	EnableMemoryOptimization *bool `json:"enableMemoryOptimization,omitempty"`
	// enableAppArmor tells the operator whether or not to enable AppArmor
	// support for this SPOD instance.
	// +optional
	// +default=false
	EnableAppArmor *bool `json:"enableAppArmor,omitempty"`
	// hostProcVolumePath is the path for specifying a custom host /proc
	// volume, which is required for the log-enricher as well as bpf-recorder
	// to retrieve the container ID for a process ID. This can be helpful for
	// nested environments, for example when using "kind".
	// +optional
	// +kubebuilder:validation:Pattern="^/proc(/.*)?$"
	HostProcVolumePath string `json:"hostProcVolumePath,omitempty"`
	// imagePullSecrets if defined, list of references to secrets in the
	// security-profiles-operator's namespace to use for pulling the images
	// from SPOD pod from a private registry.
	// +optional
	// +listType=map
	// +listMapKey=name
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// daemonResourceRequirements if defined, overwrites the default resource
	// requirements of SPOD daemon.
	// +optional
	DaemonResourceRequirements *corev1.ResourceRequirements `json:"daemonResourceRequirements,omitempty"`
	// selinux contains SELinux-specific configuration.
	// +optional
	Selinux SPODSelinuxConfig `json:"selinux,omitzero,omitempty"`
	// enricher contains log and JSON enricher configuration.
	// +optional
	Enricher SPODEnricherConfig `json:"enricher,omitzero,omitempty"`
	// webhook contains webhook configuration.
	// +optional
	Webhook SPODWebhookConfig `json:"webhook,omitzero,omitempty"`
	// scheduling contains scheduling-related configuration.
	// +optional
	Scheduling SPODSchedulingConfig `json:"scheduling,omitzero,omitempty"`
	// security contains security policy configuration.
	// +optional
	Security SPODSecurityConfig `json:"security,omitzero,omitempty"`
}

// SPODSelinuxConfig contains SELinux-specific configuration.
type SPODSelinuxConfig struct {
	// enable tells the operator whether or not to enable SELinux support for
	// this SPOD instance.
	// +optional
	Enable *bool `json:"enable,omitempty"`
	// enableRawSelinuxProfiles tells the operator whether or not to enable
	// RawSelinuxProfile support. When disabled, the RawSelinuxProfile
	// controller will not be started. Defaults to true when SELinux is enabled.
	// +optional
	EnableRawSelinuxProfiles *bool `json:"enableRawSelinuxProfiles,omitempty"`
	// typeTag is the SELinux type tag applied to the security context of SPOD.
	// +optional
	// +default="spc_t"
	TypeTag string `json:"typeTag,omitempty"`
	// options defines options specific to the SELinux functionality.
	// +optional
	Options SelinuxOptions `json:"options,omitzero,omitempty"`
}

// SPODEnricherConfig contains log enricher, JSON enricher, and BPF recorder configuration.
type SPODEnricherConfig struct {
	// enableLogEnricher tells the operator whether or not to enable log
	// enrichment support for this SPOD instance.
	// +optional
	// +default=false
	EnableLogEnricher *bool `json:"enableLogEnricher,omitempty"`
	// logEnricherFilters if defined, an optional JSON-format filter to
	// determine if log lines should be emitted for the log-enricher.
	// +optional
	LogEnricherFilters string `json:"logEnricherFilters,omitempty"`
	// logEnricherSource determines which source should be used for audit
	// logs. This defaults to "Auditd", but can be switched to "Bpf" on
	// systems where auditd is unavailable.
	// +optional
	LogEnricherSource LogEnricherSource `json:"logEnricherSource,omitempty"`
	// enableJsonEnricher tells the operator whether or not to enable audit
	// JSON enrichment support for this SPOD instance.
	// +optional
	// +default=false
	EnableJsonEnricher *bool `json:"enableJsonEnricher,omitempty"`
	// jsonEnricherFilters if defined, an optional JSON-format filter to
	// determine if log lines should be emitted for the json-enricher.
	// +optional
	JsonEnricherFilters string `json:"jsonEnricherFilters,omitempty"`
	// jsonEnricherOptions defines options specific to the JSON enricher.
	// +optional
	JsonEnricherOptions *JsonEnricherOptions `json:"jsonEnricherOptions,omitempty"`
	// enableBpfRecorder tells the operator whether or not to enable bpf
	// recorder support for this SPOD instance.
	// +optional
	// +default=false
	EnableBpfRecorder *bool `json:"enableBpfRecorder,omitempty"`
}

// SPODWebhookConfig contains webhook configuration.
type SPODWebhookConfig struct {
	// staticConfig indicates whether the webhook configuration and its
	// related resources are statically deployed. In this case, the operator
	// will not create or update the webhook configuration and its related
	// resources.
	// +optional
	// +default=false
	StaticConfig *bool `json:"staticConfig,omitempty"`
	// options set custom namespace selectors and failure mode for SPO's webhooks.
	// +optional
	// +listType=map
	// +listMapKey=name
	Options []WebhookOptions `json:"options,omitempty"`
}

// SPODSchedulingConfig contains scheduling-related configuration.
type SPODSchedulingConfig struct {
	// tolerations if specified, the SPOD's tolerations.
	// +optional
	// +listType=atomic
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// affinity if specified, the SPOD's affinity.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`
	// priorityClassName if defined, indicates the SPOD pod priority class.
	// +optional
	// +default="system-node-critical"
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// SPODSecurityConfig contains security policy configuration.
type SPODSecurityConfig struct {
	// allowedSyscalls if specified, a list of system calls which are
	// allowed in seccomp profiles.
	// +optional
	// +listType=set
	AllowedSyscalls []string `json:"allowedSyscalls,omitempty"`
	// allowedSeccompActions if specified, a list of allowed seccomp actions.
	// +optional
	// +listType=atomic
	AllowedSeccompActions []seccompapi.Action `json:"allowedSeccompActions,omitempty"`
	// disableOciArtifactSignatureVerification can be used to disable OCI
	// artifact signature verification.
	// +optional
	// +default=false
	DisableOCIArtifactSignatureVerification *bool `json:"disableOciArtifactSignatureVerification,omitempty"`

	// allowedIdentityRegexp regexp for allowed identity when verifying the signature of OCI
	// image used to distribute the base profile in the cluster.
	// +optional
	// +default=".*"
	AllowedIdentityRegexp string `json:"allowedIdentityRegexp,omitempty"`

	// allowedOidcIssuerRegexp regexp for allowed Oidc issuer when verifying the signature of OCI
	// image used to distribute the base profile in the cluster.
	// +optional
	// +default=".*"
	AllowedOidcIssuerRegexp string `json:"allowedOidcIssuerRegexp,omitempty"`
}

// SPODState defines the state that the spod is in.
// +kubebuilder:validation:Enum=Pending;Creating;Updating;Running;Error
type SPODState string

const (
	// The SPOD instance is pending installation.
	SPODStatePending SPODState = "Pending"
	// The SPOD instance is being created.
	SPODStateCreating SPODState = "Creating"
	// The SPOD instance is being updated.
	SPODStateUpdating SPODState = "Updating"
	// The SPOD instance was installed successfully.
	SPODStateRunning SPODState = "Running"
	// The SPOD instance couldn't be installed.
	SPODStateError SPODState = "Error"
)

// SPODStatus defines the observed state of SPOD.
type SPODStatus struct {
	common.ConditionedStatus `json:",inline"`
	// state represents the state that the policy is in. Can be:
	// Pending, Creating, Updating, Running or Error
	// +optional
	State SPODState `json:"state,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityProfilesOperatorDaemon is the Schema to configure the spod deployment.
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=securityprofilesoperatordaemons,shortName=spod
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.state`
type SecurityProfilesOperatorDaemon struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the SecurityProfilesOperatorDaemon.
	// +optional
	Spec SPODSpec `json:"spec,omitempty"`
	// status contains the observed state of the SecurityProfilesOperatorDaemon.
	// +optional
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
	s.SetConditions(common.Pending())
}

func (s *SPODStatus) StateCreating() {
	s.State = SPODStateCreating
	s.SetConditions(common.Creating())
}

func (s *SPODStatus) StateUpdating() {
	s.State = SPODStateUpdating
	s.SetConditions(common.Updating())
}

func (s *SPODStatus) StateRunning() {
	s.State = SPODStateRunning
	s.SetConditions(common.Available())
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(&SecurityProfilesOperatorDaemon{}, &SecurityProfilesOperatorDaemonList{})
}
