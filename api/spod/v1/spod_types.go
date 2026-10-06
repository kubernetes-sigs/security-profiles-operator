/*
Copyright The Kubernetes Authors.

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
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/security-profiles-operator/api/common"
	seccompapi "sigs.k8s.io/security-profiles-operator/api/seccomp"
)

// SelinuxOptions defines options specific to the SELinux
// functionality of the SecurityProfilesOperator.
type SelinuxOptions struct {
	// allowedSystemProfiles lists the profiles coming from the system itself
	// that are allowed to be inherited by workloads. Use this with care,
	// as this might provide a lot of permissions depending on the policy.
	// Each entry may only contain alphanumeric characters, '.', '-' and '_',
	// like the names of the inherited system profiles it gets compared to.
	// +optional
	// +default=["container"]
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[-a-zA-Z0-9._]+$`
	AllowedSystemProfiles []string `json:"allowedSystemProfiles,omitempty"`

	// deniedTypes if specified, a list of SELinux types which are
	// denied in SELinux profiles.
	// Each entry gets compared to the types of SELinux profiles, so it may
	// only contain alphanumeric characters, '.', '-' and '_', or be '@self'.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^([-a-zA-Z0-9._]+|@self)$`
	DeniedTypes []string `json:"deniedTypes,omitempty"`

	// deniedClasses if specified, a list of SELinux object classes which are
	// denied in SELinux profiles.
	// Each entry gets compared to the object classes of SELinux profiles, so
	// it may only contain alphanumeric characters, '.', '-' and '_'.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[-a-zA-Z0-9._]+$`
	DeniedClasses []string `json:"deniedClasses,omitempty"`

	// deniedPermissions if specified, a list of SELinux permissions which are
	// denied in SELinux profiles.
	// Each entry gets compared to the permissions of SELinux profiles, so it
	// may only contain alphanumeric characters, '.', '-' and '_'.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[-a-zA-Z0-9._]+$`
	DeniedPermissions []string `json:"deniedPermissions,omitempty"`

	// allowedTypes if specified, a list of SELinux types which are removed
	// from the built-in denylist. Use this with care, as it relaxes a safe
	// default for every translated policy.
	// Each entry gets compared to the types of SELinux profiles, so it may
	// only contain alphanumeric characters, '.', '-' and '_', or be '@self'.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^([-a-zA-Z0-9._]+|@self)$`
	AllowedTypes []string `json:"allowedTypes,omitempty"`

	// allowedClasses if specified, a list of SELinux object classes which are
	// removed from the built-in denylist. Use this with care, as it relaxes a
	// safe default for every translated policy.
	// Each entry gets compared to the object classes of SELinux profiles, so
	// it may only contain alphanumeric characters, '.', '-' and '_'.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[-a-zA-Z0-9._]+$`
	AllowedClasses []string `json:"allowedClasses,omitempty"`

	// allowedPermissions if specified, a list of SELinux permissions which are
	// removed from the built-in denylist. Use this with care, as it relaxes a
	// safe default for every translated policy.
	// Each entry gets compared to the permissions of SELinux profiles, so it
	// may only contain alphanumeric characters, '.', '-' and '_'.
	// +optional
	// +listType=set
	// +kubebuilder:validation:items:Pattern=`^[-a-zA-Z0-9._]+$`
	AllowedPermissions []string `json:"allowedPermissions,omitempty"`
}

// JsonEnricherOptions defines options specific to the JSON enricher.
type JsonEnricherOptions struct {
	// auditLogIntervalSeconds specifies the interval, in seconds, at which
	// the accumulated audit log data is output in JSON format. For each
	// process, syscalls occurring within this interval are grouped together.
	// The default is 60 seconds. Increasing this interval will reduce the
	// rate at which logs are written.
	// +optional
	// +default=60
	// +kubebuilder:validation:Minimum=1
	//nolint:kubeapilinter // changing the pointer to a value would break the Go API
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
	// +default=100
	// +kubebuilder:validation:Minimum=1
	//nolint:kubeapilinter // changing the pointer to a value would break the Go API
	AuditLogMaxSize *int32 `json:"auditLogMaxSize,omitempty"`
	// auditLogMaxBackups specifies the maximum number of old audit log
	// files to retain. If it is unset or 0, 10 old log files are retained,
	// unless auditLogMaxAge is set, which then alone decides about removing
	// them.
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
	// name specifies which webhook to configure. Valid values are
	// binding.spo.io, recording.spo.io, execmetadata.spo.io and
	// nodedebuggingpod.spo.io.
	// +required
	// +kubebuilder:validation:Enum=binding.spo.io;recording.spo.io;execmetadata.spo.io;nodedebuggingpod.spo.io
	Name string `json:"name,omitempty"`
	// failurePolicy sets the webhook failure policy.
	// +optional
	// +kubebuilder:validation:Enum=Ignore;Fail
	//nolint:kubeapilinter // changing the pointer to a value would break the Go API
	FailurePolicy *admissionregv1.FailurePolicyType `json:"failurePolicy,omitempty"`
	// namespaceSelector sets the webhook's namespace selector. It has to be a
	// valid label selector, which the webhook configuration requires.
	// +optional
	//nolint:lll // CEL rules cannot be wrapped
	// +kubebuilder:validation:XValidation:rule="!has(self.matchExpressions) || self.matchExpressions.all(e, has(e.values) && size(e.values) > 0 ? (e.operator == 'In' || e.operator == 'NotIn') : (e.operator == 'Exists' || e.operator == 'DoesNotExist'))",message="matchExpressions operator must be In, NotIn, Exists or DoesNotExist, In and NotIn require values, Exists and DoesNotExist must not have values"
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// objectSelector sets the webhook's object selector. It has to be a
	// valid label selector, which the webhook configuration requires.
	// +optional
	//nolint:lll // CEL rules cannot be wrapped
	// +kubebuilder:validation:XValidation:rule="!has(self.matchExpressions) || self.matchExpressions.all(e, has(e.values) && size(e.values) > 0 ? (e.operator == 'In' || e.operator == 'NotIn') : (e.operator == 'Exists' || e.operator == 'DoesNotExist'))",message="matchExpressions operator must be In, NotIn, Exists or DoesNotExist, In and NotIn require values, Exists and DoesNotExist must not have values"
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
	// +kubebuilder:validation:Maximum=10
	//nolint:kubeapilinter // zero is the default verbosity, so unset and zero are equivalent
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
	// enableInsecureMetricsAccess enables unauthenticated access to the metrics
	// endpoint. This will disable TLS and authentication for the metrics endpoint.
	// +optional
	// +default=false
	EnableInsecureMetricsAccess *bool `json:"enableInsecureMetricsAccess,omitempty"`
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
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
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
	// +default={}
	//nolint:kubeapilinter // a pointer would break the Go API, the defaults fill the struct
	Selinux SPODSelinuxConfig `json:"selinux,omitzero"`
	// enricher contains log and JSON enricher configuration.
	// +optional
	// +default={}
	//nolint:kubeapilinter // a pointer would break the Go API, the defaults fill the struct
	Enricher SPODEnricherConfig `json:"enricher,omitzero"`
	// webhook contains webhook configuration.
	// +optional
	// +default={}
	//nolint:kubeapilinter // a pointer would break the Go API, the defaults fill the struct
	Webhook SPODWebhookConfig `json:"webhook,omitzero"`
	// scheduling contains scheduling-related configuration.
	// +optional
	// +default={}
	//nolint:kubeapilinter // a pointer would break the Go API, the defaults fill the struct
	Scheduling SPODSchedulingConfig `json:"scheduling,omitzero"`
	// security contains security policy configuration.
	// +optional
	// +default={}
	//nolint:kubeapilinter // a pointer would break the Go API, the defaults fill the struct
	Security SPODSecurityConfig `json:"security,omitzero"`
}

// SPODSelinuxConfig contains SELinux-specific configuration.
type SPODSelinuxConfig struct {
	// enable tells the operator whether or not to enable SELinux support for
	// this SPOD instance. If unset, SELinux support is enabled on OpenShift
	// and disabled everywhere else.
	// +optional
	Enable *bool `json:"enable,omitempty"`
	// enableRawSelinuxProfiles tells the operator whether or not to enable
	// RawSelinuxProfile support. When disabled, the RawSelinuxProfile
	// controller will not be started. It only has an effect when SELinux
	// support is enabled. Defaults to true.
	// +optional
	// +default=true
	EnableRawSelinuxProfiles *bool `json:"enableRawSelinuxProfiles,omitempty"`
	// typeTag is the SELinux type tag applied to the security context of SPOD.
	// +optional
	// +default="spc_t"
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	TypeTag string `json:"typeTag,omitempty"`
	// options defines options specific to the SELinux functionality.
	// +optional
	// +default={}
	//nolint:kubeapilinter // a pointer would break the Go API, the defaults fill the struct
	Options SelinuxOptions `json:"options,omitzero"`
	// customTemplatesConfigMap if defined, names a ConfigMap containing .cil
	// files that replace the bundled selinuxd templates entirely. The ConfigMap
	// must exist in the same namespace as the SPOD daemonset. Use this on
	// distributions (e.g. Flatcar Linux) whose SELinux policy base is incompatible
	// with the templates shipped with selinuxd. Note: changes to the ConfigMap
	// contents require restarting the DaemonSet pods to take effect.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	CustomTemplatesConfigMap string `json:"customTemplatesConfigMap,omitempty"`
}

// SPODEnricherConfig contains log enricher, JSON enricher, and BPF recorder configuration.
type SPODEnricherConfig struct {
	// enableLogEnricher tells the operator whether or not to enable log
	// enrichment support for this SPOD instance.
	// +optional
	// +default=false
	EnableLogEnricher *bool `json:"enableLogEnricher,omitempty"`
	// logEnricherFilters if defined, an optional JSON-format filter to
	// determine if log lines should be emitted for the log-enricher. It is
	// passed as a single command line argument, so it is limited to 64 KiB.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	LogEnricherFilters string `json:"logEnricherFilters,omitempty"`
	// logEnricherSource determines which source should be used for audit
	// logs. This defaults to "Auditd", but can be switched to "Bpf" on
	// systems where auditd is unavailable.
	// +optional
	// +default="Auditd"
	LogEnricherSource LogEnricherSource `json:"logEnricherSource,omitempty"`
	// enableJsonEnricher tells the operator whether or not to enable audit
	// JSON enrichment support for this SPOD instance.
	// +optional
	// +default=false
	EnableJsonEnricher *bool `json:"enableJsonEnricher,omitempty"`
	// jsonEnricherFilters if defined, an optional JSON-format filter to
	// determine if log lines should be emitted for the json-enricher. It is
	// passed as a single command line argument, so it is limited to 64 KiB.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	JsonEnricherFilters string `json:"jsonEnricherFilters,omitempty"`
	// jsonEnricherOptions defines options specific to the JSON enricher.
	// +optional
	JsonEnricherOptions *JsonEnricherOptions `json:"jsonEnricherOptions,omitempty"`
	// enableBpfRecorder tells the operator whether or not to enable bpf
	// recorder support for this SPOD instance.
	// +optional
	// +default=false
	EnableBpfRecorder *bool `json:"enableBpfRecorder,omitempty"`
	// enableExecMetadata tells the operator whether the exec metadata
	// webhook gets deployed together with the JSON enricher. The webhook
	// rewrites every "kubectl exec" into the recorded namespaces to run
	// through the env binary of the container image, so that the enricher
	// can attribute the syscalls to the exec request. Disable it for
	// clusters with images which do not ship an env binary. It has no
	// effect while the JSON enricher is disabled.
	// +optional
	// +default=true
	EnableExecMetadata *bool `json:"enableExecMetadata,omitempty"`
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
	// There can be at most one entry for each of the four webhooks.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=4
	Options []WebhookOptions `json:"options,omitempty"`
	// tolerations if specified, the webhook's tolerations. When not set,
	// the webhook inherits the daemon's tolerations from the scheduling config.
	// +optional
	// +listType=atomic
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
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
	// The pods of the managed webhook use system-cluster-critical, unless a
	// priority class other than the default is set here, which then applies
	// to them as well.
	// +optional
	// +default="system-node-critical"
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	PriorityClassName string `json:"priorityClassName,omitempty"`
}

// SPODSecurityConfig contains security policy configuration.
type SPODSecurityConfig struct {
	// allowedSyscalls if specified, a list of system calls which are
	// allowed in seccomp profiles.
	// +optional
	// +listType=set
	AllowedSyscalls []string `json:"allowedSyscalls,omitempty"`
	// allowedSeccompActions if specified, limits the seccomp actions whose
	// syscalls are checked against allowedSyscalls. Valid values are
	// SCMP_ACT_ALLOW, SCMP_ACT_LOG, SCMP_ACT_TRACE and SCMP_ACT_NOTIFY. If
	// unset, all of them are checked.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=4
	//nolint:lll // CEL rules cannot be wrapped
	// +kubebuilder:validation:XValidation:rule="self.all(a, a in ['SCMP_ACT_ALLOW', 'SCMP_ACT_LOG', 'SCMP_ACT_TRACE', 'SCMP_ACT_NOTIFY'])",message="allowedSeccompActions may only contain SCMP_ACT_ALLOW, SCMP_ACT_LOG, SCMP_ACT_TRACE and SCMP_ACT_NOTIFY"
	AllowedSeccompActions []seccompapi.Action `json:"allowedSeccompActions,omitempty"`
	// disableOciArtifactSignatureVerification can be used to disable OCI
	// artifact signature verification.
	// +optional
	// +default=false
	DisableOCIArtifactSignatureVerification *bool `json:"disableOciArtifactSignatureVerification,omitempty"`

	// allowedIdentityRegexp regexp for allowed identity when verifying the signature of OCI
	// image used to distribute the base profile in the cluster.
	// The default ".*" matches any identity, which means a signature from any
	// signer is accepted. That only proves the artifact was signed by somebody,
	// not by somebody trusted, so set this to the identities you trust.
	// +optional
	// +default=".*"
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	AllowedIdentityRegexp string `json:"allowedIdentityRegexp,omitempty"`

	// allowedOidcIssuerRegexp regexp for allowed Oidc issuer when verifying the signature of OCI
	// image used to distribute the base profile in the cluster.
	// As with allowedIdentityRegexp, the default ".*" matches any issuer.
	// +optional
	// +default=".*"
	//nolint:kubeapilinter // released v1 API: empty means unset, a MinLength would reject existing manifests
	AllowedOidcIssuerRegexp string `json:"allowedOidcIssuerRegexp,omitempty"`

	// signatureVerification configures how the signatures of OCI base
	// profiles get verified, beyond the identity and issuer regexps. It
	// applies to base profiles outside of the official repositories of this
	// project only (registry.k8s.io/security-profiles-operator/ and its
	// staging repository). Official base profiles are always verified against
	// the official keyless signers and the public Sigstore trusted root, so
	// that a key or identity for private base profiles does not break them.
	// It has no effect while disableOciArtifactSignatureVerification is true.
	// +optional
	//nolint:kubeapilinter // a nil pointer marks the whole verification config as unset
	SignatureVerification *SPODSignatureVerification `json:"signatureVerification,omitempty"`
}

// SPODSignatureVerification configures the verification of the signatures of
// OCI base profiles outside of the official repositories.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:XValidation:rule="!has(self.offline) || !self.offline || has(self.trustedRootConfigMapRef)",message="offline requires trustedRootConfigMapRef"
//
//nolint:lll // CEL rules cannot be wrapped
type SPODSignatureVerification struct {
	// publicKeySecretRef selects the key of a Secret in the operator
	// namespace which holds a PEM encoded public key. If set, the signatures
	// are verified with that key instead of a keyless certificate, and the
	// identity and issuer settings are ignored. The Secret and the key have
	// to exist, optional is not supported.
	// +optional
	PublicKeySecretRef *corev1.SecretKeySelector `json:"publicKeySecretRef,omitempty"`

	// allowedIdentity is the exact identity which the keyless signing
	// certificate has to be issued for, for example the workflow URL of a
	// CI job. It takes precedence over allowedIdentityRegexp.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	AllowedIdentity string `json:"allowedIdentity,omitempty"`

	// allowedOidcIssuer is the exact OIDC issuer of the keyless signing
	// certificate. It takes precedence over allowedOidcIssuerRegexp.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	AllowedOidcIssuer string `json:"allowedOidcIssuer,omitempty"`

	// trustedRootConfigMapRef selects the key of a ConfigMap in the operator
	// namespace which holds a Sigstore trusted root in JSON format. It
	// replaces the public Sigstore trusted root, for example for a private
	// Sigstore deployment or an air-gapped cluster. It is required if
	// offline is true. The ConfigMap and the key have to exist, optional is
	// not supported.
	// +optional
	TrustedRootConfigMapRef *corev1.ConfigMapKeySelector `json:"trustedRootConfigMapRef,omitempty"`

	// offline skips every network access during the verification: the
	// transparency log entry bundled with the signature is verified against
	// the trusted root of trustedRootConfigMapRef, which is required then.
	// Without offline, the daemon fetches the public Sigstore trusted root
	// through TUF unless trustedRootConfigMapRef is set. Defaults to false.
	// +optional
	Offline *bool `json:"offline,omitempty"`
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
	// observedGeneration is the generation of the SPOD which the state and
	// the conditions were computed for.
	// +optional
	// +kubebuilder:validation:Minimum=0
	//nolint:kubeapilinter // zero means that no generation got observed yet
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityProfilesOperatorDaemon is the Schema to configure the spod deployment.
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=securityprofilesoperatordaemons,shortName=spod
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SecurityProfilesOperatorDaemon struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the SecurityProfilesOperatorDaemon.
	// +optional
	Spec SPODSpec `json:"spec,omitempty"` //nolint:kubeapilinter // spec is a value by convention
	// status contains the observed state of the SecurityProfilesOperatorDaemon.
	// +optional
	Status SPODStatus `json:"status,omitzero"` //nolint:kubeapilinter // status is a value by convention
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

// StateError marks the SPOD as not reconcilable with the provided reason.
func (s *SPODStatus) StateError(message string) {
	s.State = SPODStateError
	s.SetConditions(common.Unavailable(message))
}

// SetObservedGeneration records the generation of the SPOD which the state
// and the Ready condition were computed for.
func (s *SPODStatus) SetObservedGeneration(generation int64) {
	s.ObservedGeneration = generation

	for i := range s.Conditions {
		if s.Conditions[i].Type == string(common.TypeReady) {
			s.Conditions[i].ObservedGeneration = generation
		}
	}
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(
			GroupVersion,
			&SecurityProfilesOperatorDaemon{},
			&SecurityProfilesOperatorDaemonList{},
		)

		return nil
	})
}
