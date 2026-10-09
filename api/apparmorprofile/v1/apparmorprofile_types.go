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
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	// Entries of the form "ptrace (read)," are deprecated: use
	// abstract.ptrace instead. They are still accepted and rendered as ptrace
	// rules, but support for them will be removed in a future API version.
	// +optional
	// +listType=set
	//nolint:lll // the pattern cannot be wrapped; braces outside of variables never loaded in apparmor_parser
	// +kubebuilder:validation:items:Pattern=`^(?:/(?:[a-zA-Z0-9_./*?+@ -]|@\{[a-zA-Z0-9_]+\})*|ptrace\s*\([a-zA-Z]+\),(?:\s*#.*)?)$`
	AllowedExecutables []string `json:"allowedExecutables,omitempty"`
	// allowedLibraries is a list of allowed libraries.
	// Entries of the form "ptrace (read)," are deprecated: use
	// abstract.ptrace instead. They are still accepted and rendered as ptrace
	// rules, but support for them will be removed in a future API version.
	// +optional
	// +listType=set
	//nolint:lll // the pattern cannot be wrapped; braces outside of variables never loaded in apparmor_parser
	// +kubebuilder:validation:items:Pattern=`^(?:/(?:[a-zA-Z0-9_./*?+@ -]|@\{[a-zA-Z0-9_]+\})*|ptrace\s*\([a-zA-Z]+\),(?:\s*#.*)?)$`
	AllowedLibraries []string `json:"allowedLibraries,omitempty"`
}

// AppArmorFsRules stores the rules for file system access.
type AppArmorFsRules struct {
	// readOnlyPaths is a list of allowed read only file paths.
	// Entries of the form "ptrace (read)," are deprecated: use
	// abstract.ptrace instead. They are still accepted and rendered as ptrace
	// rules, but support for them will be removed in a future API version.
	// +optional
	// +listType=set
	//nolint:lll // the pattern cannot be wrapped; braces outside of variables never loaded in apparmor_parser
	// +kubebuilder:validation:items:Pattern=`^(?:/(?:[a-zA-Z0-9_./*?+@ -]|@\{[a-zA-Z0-9_]+\})*|ptrace\s*\([a-zA-Z]+\),(?:\s*#.*)?)$`
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`
	// writeOnlyPaths is a list of allowed write only file paths.
	// Entries of the form "ptrace (read)," are deprecated: use
	// abstract.ptrace instead. They are still accepted and rendered as ptrace
	// rules, but support for them will be removed in a future API version.
	// +optional
	// +listType=set
	//nolint:lll // the pattern cannot be wrapped; braces outside of variables never loaded in apparmor_parser
	// +kubebuilder:validation:items:Pattern=`^(?:/(?:[a-zA-Z0-9_./*?+@ -]|@\{[a-zA-Z0-9_]+\})*|ptrace\s*\([a-zA-Z]+\),(?:\s*#.*)?)$`
	WriteOnlyPaths []string `json:"writeOnlyPaths,omitempty"`
	// readWritePaths is a list of allowed read write file paths.
	// Entries of the form "ptrace (read)," are deprecated: use
	// abstract.ptrace instead. They are still accepted and rendered as ptrace
	// rules, but support for them will be removed in a future API version.
	// +optional
	// +listType=set
	//nolint:lll // the pattern cannot be wrapped; braces outside of variables never loaded in apparmor_parser
	// +kubebuilder:validation:items:Pattern=`^(?:/(?:[a-zA-Z0-9_./*?+@ -]|@\{[a-zA-Z0-9_]+\})*|ptrace\s*\([a-zA-Z]+\),(?:\s*#.*)?)$`
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
	// allowedCapabilities is a list of allowed capabilities, written in
	// lower case without the "CAP_" prefix, for example "net_bind_service".
	// +optional
	// +listType=set
	//nolint:lll // the capability pattern cannot be wrapped
	// +kubebuilder:validation:items:Pattern=`^(chown|dac_override|dac_read_search|fowner|fsetid|kill|setgid|setuid|setpcap|linux_immutable|net_bind_service|net_broadcast|net_admin|net_raw|ipc_lock|ipc_owner|sys_module|sys_rawio|sys_chroot|sys_ptrace|sys_pacct|sys_admin|sys_boot|sys_nice|sys_resource|sys_time|sys_tty_config|mknod|lease|audit_write|audit_control|setfcap|mac_override|mac_admin|syslog|wake_alarm|block_suspend|audit_read|perfmon|bpf|checkpoint_restore)$`
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
}

// AppArmorPtraceAccess is an access which an AppArmor ptrace rule grants.
// +kubebuilder:validation:Enum=read;readby;trace;tracedby
type AppArmorPtraceAccess string

const (
	// AppArmorPtraceAccessRead allows reading the state of the peer, for
	// example through /proc/<pid>/maps.
	AppArmorPtraceAccessRead AppArmorPtraceAccess = "read"
	// AppArmorPtraceAccessReadBy allows the peer to read the state of the
	// confined process.
	AppArmorPtraceAccessReadBy AppArmorPtraceAccess = "readby"
	// AppArmorPtraceAccessTrace allows tracing the peer.
	AppArmorPtraceAccessTrace AppArmorPtraceAccess = "trace"
	// AppArmorPtraceAccessTracedBy allows the peer to trace the confined
	// process.
	AppArmorPtraceAccessTracedBy AppArmorPtraceAccess = "tracedby"
)

// AppArmorPtraceRules stores the rules for ptrace access. They are rendered as
// a single "ptrace (<allowedAccess>) peer=<peer>," rule.
type AppArmorPtraceRules struct {
	// allowedAccess is the list of allowed ptrace accesses.
	// Valid values are "read", "readby", "trace" and "tracedby".
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=4
	AllowedAccess []AppArmorPtraceAccess `json:"allowedAccess,omitempty"`
	// peer limits the rule to processes confined by the AppArmor profiles
	// matching this name, for example "@{profile_name}" for the profile
	// itself. Without a peer, the rule applies to every process.
	// It may contain letters, digits, "_", ".", "/", "-", the globs "*" and
	// "?", and the variable "@{profile_name}".
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^(?:[a-zA-Z0-9_./*?-]|@\{profile_name\})+$`
	Peer string `json:"peer,omitempty"`
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
	// ptrace defines rules for ptrace access.
	// +optional
	//nolint:kubeapilinter // a pointer like the other rules, unset renders no rule
	Ptrace *AppArmorPtraceRules `json:"ptrace,omitempty"`
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
	//nolint:kubeapilinter // an empty abstract is a valid deny-all profile
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
	// activeWorkloads lists the pods currently using this profile as
	// namespace/name, sorted and limited to the first 1000 of them.
	// +optional
	// +listType=set
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
	// activeWorkloadsCount is the number of pods currently using this
	// profile, which can be more than activeWorkloads lists.
	// +optional
	// +kubebuilder:validation:Minimum=1
	ActiveWorkloadsCount int32 `json:"activeWorkloadsCount,omitempty"`
}

// +kubebuilder:object:root=true

// AppArmorProfile is a cluster level specification for an AppArmor profile.
// +kubebuilder:storageversion
// +kubebuilder:resource:shortName=aa,scope=Cluster,categories=spo
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type AppArmorProfile struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the AppArmor profile.
	// +optional
	//nolint:kubeapilinter // spec has no required fields and is a value by convention
	Spec AppArmorProfileSpec `json:"spec,omitzero"`
	// status contains the observed state of the AppArmor profile.
	// +optional
	Status AppArmorProfileStatus `json:"status,omitzero"` //nolint:kubeapilinter // status is a value by convention
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
	recording, recordingNamespace string,
) ([]metav1.Object, error) {
	return profilebasev1.ListProfilesByRecording(
		ctx,
		cli,
		recording,
		recordingNamespace,
		&AppArmorProfileList{},
	)
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
	// Items is the list of AppArmorProfile objects.
	Items []AppArmorProfile `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init the scheme
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, &AppArmorProfile{}, &AppArmorProfileList{})

		return nil
	})
}

func (sp *AppArmorProfile) GetProfileName() string {
	return sp.GetName()
}
