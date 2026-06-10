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

package v1beta1

import (
	"context"
	"path"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	seccompapi "sigs.k8s.io/security-profiles-operator/api/seccomp"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// Ensure SeccompProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
var (
	_ profilebase.StatusBaseUser      = &SeccompProfile{}
	_ profilebase.SecurityProfileBase = &SeccompProfile{}
)

const ExtJSON = ".json"

type Action = seccompapi.Action

const (
	ActKill        = seccompapi.ActKill
	ActKillProcess = seccompapi.ActKillProcess
	ActKillThread  = seccompapi.ActKillThread
	ActTrap        = seccompapi.ActTrap
	ActErrno       = seccompapi.ActErrno
	ActTrace       = seccompapi.ActTrace
	ActAllow       = seccompapi.ActAllow
	ActLog         = seccompapi.ActLog
	ActNotify      = seccompapi.ActNotify
)

type Operator = seccompapi.Operator

const (
	OpNotEqual     = seccompapi.OpNotEqual
	OpLessThan     = seccompapi.OpLessThan
	OpLessEqual    = seccompapi.OpLessEqual
	OpEqualTo      = seccompapi.OpEqualTo
	OpGreaterEqual = seccompapi.OpGreaterEqual
	OpGreaterThan  = seccompapi.OpGreaterThan
	OpMaskedEqual  = seccompapi.OpMaskedEqual
)

// SeccompProfileSpec defines the desired state of SeccompProfile.
type SeccompProfileSpec struct {
	// Common spec fields for all profiles.
	profilebase.SpecBase `json:",inline"`

	// baseProfileName is the name of base profile (in the same namespace) that
	// will be unioned into this profile. Base profiles can be references as
	// remote OCI artifacts as well when prefixed with `oci://`.
	// +optional
	BaseProfileName string `json:"baseProfileName,omitempty"`

	// defaultAction is the default action for seccomp. Valid values are:
	// SCMP_ACT_KILL, SCMP_ACT_KILL_PROCESS, SCMP_ACT_KILL_THREAD,
	// SCMP_ACT_TRAP, SCMP_ACT_ERRNO, SCMP_ACT_TRACE, SCMP_ACT_ALLOW,
	// SCMP_ACT_LOG, SCMP_ACT_NOTIFY.
	// +required
	//nolint:lll // required for kubebuilder
	// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG;SCMP_ACT_NOTIFY
	DefaultAction Action `json:"defaultAction,omitempty"`
	// architectures specifies the architecture used for system calls.
	// +optional
	// +listType=set
	Architectures []Arch `json:"architectures,omitempty"`
	// listenerPath is the path of UNIX domain socket to contact a seccomp
	// agent for SCMP_ACT_NOTIFY.
	// +optional
	// +kubebuilder:validation:Pattern=`^/var/run/security-profiles-operator/[a-zA-Z0-9_\-\.]+$`
	ListenerPath string `json:"listenerPath,omitempty"`
	// listenerMetadata contains opaque data to pass to the seccomp agent.
	// +optional
	ListenerMetadata string `json:"listenerMetadata,omitempty"`
	// syscalls match a syscall in seccomp. While this property is optional,
	// some values of defaultAction are not useful without syscalls entries.
	// For example, if defaultAction is SCMP_ACT_KILL and syscalls is empty
	// or unset, the kernel will kill the container process on its first syscall.
	// +optional
	// +listType=atomic
	Syscalls []Syscall `json:"syscalls,omitempty"`

	// Additional properties from OCI runtime spec

	// flags is a list of flags to use with seccomp(2).
	// +optional
	// +listType=set
	Flags []Flag `json:"flags,omitempty"`
}

// +kubebuilder:validation:Enum=SCMP_ARCH_NATIVE;SCMP_ARCH_X86;SCMP_ARCH_X86_64;SCMP_ARCH_X32;SCMP_ARCH_ARM;SCMP_ARCH_AARCH64;SCMP_ARCH_MIPS;SCMP_ARCH_MIPS64;SCMP_ARCH_MIPS64N32;SCMP_ARCH_MIPSEL;SCMP_ARCH_MIPSEL64;SCMP_ARCH_MIPSEL64N32;SCMP_ARCH_PPC;SCMP_ARCH_PPC64;SCMP_ARCH_PPC64LE;SCMP_ARCH_S390;SCMP_ARCH_S390X;SCMP_ARCH_PARISC;SCMP_ARCH_PARISC64;SCMP_ARCH_RISCV64
//
//nolint:lll // required for kubebuilder
type Arch string

// +kubebuilder:validation:Enum=SECCOMP_FILTER_FLAG_TSYNC;SECCOMP_FILTER_FLAG_LOG;SECCOMP_FILTER_FLAG_SPEC_ALLOW;SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
//
//nolint:lll // required for kubebuilder
type Flag string

// Syscall defines a syscall in seccomp.
type Syscall struct {
	// names specifies the names of the syscalls.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Names []string `json:"names,omitempty"`
	// action is the action for seccomp rules. Valid values are:
	// SCMP_ACT_KILL, SCMP_ACT_KILL_PROCESS, SCMP_ACT_KILL_THREAD,
	// SCMP_ACT_TRAP, SCMP_ACT_ERRNO, SCMP_ACT_TRACE, SCMP_ACT_ALLOW,
	// SCMP_ACT_LOG, SCMP_ACT_NOTIFY.
	// +required
	//nolint:lll // required for kubebuilder
	// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG;SCMP_ACT_NOTIFY
	Action Action `json:"action,omitempty"`
	// errnoRet is the errno return code to use. Some actions like
	// SCMP_ACT_ERRNO and SCMP_ACT_TRACE allow to specify the errno
	// code to return.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ErrnoRet int32 `json:"errnoRet,omitempty"`
	// args defines the specific syscall arguments in seccomp.
	// +optional
	// +kubebuilder:validation:MaxItems=6
	// +listType=atomic
	Args []Arg `json:"args,omitempty"`
}

// Arg defines the specific syscall in seccomp.
type Arg struct {
	// index is the index for syscall arguments in seccomp.
	// +required
	// +kubebuilder:validation:Minimum=0
	Index *int32 `json:"index,omitempty"`
	// value is the value for syscall arguments in seccomp.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Value int64 `json:"value,omitempty"`
	// valueTwo is the second value for syscall arguments in seccomp.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ValueTwo int64 `json:"valueTwo,omitempty"`
	// op is the operator for syscall arguments in seccomp. Valid values are:
	// SCMP_CMP_NE, SCMP_CMP_LT, SCMP_CMP_LE, SCMP_CMP_EQ, SCMP_CMP_GE,
	// SCMP_CMP_GT, SCMP_CMP_MASKED_EQ.
	// +required
	//nolint:lll // required for kubebuilder
	// +kubebuilder:validation:Enum=SCMP_CMP_NE;SCMP_CMP_LT;SCMP_CMP_LE;SCMP_CMP_EQ;SCMP_CMP_GE;SCMP_CMP_GT;SCMP_CMP_MASKED_EQ
	Op Operator `json:"op,omitempty"`
}

// SeccompProfileStatus contains status of the deployed SeccompProfile.
type SeccompProfileStatus struct {
	profilebase.StatusBase `json:",inline"`
	// path is the file path of the installed seccomp profile on the node.
	// +optional
	Path string `json:"path,omitempty"`
	// activeWorkloads lists the workloads currently using this profile.
	// +optional
	// +listType=set
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
	// localhostProfile is the path that should be provided to the
	// `securityContext.seccompProfile.localhostProfile` field of a Pod
	// or container spec.
	// +optional
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

// +kubebuilder:object:root=true

// SeccompProfile is a cluster level specification for a seccomp profile.
// See https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#seccomp
// +kubebuilder:resource:shortName=sp,scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="LocalhostProfile",type=string,priority=10,JSONPath=`.status.localhostProfile`
type SeccompProfile struct {
	metav1.TypeMeta `json:",inline"`
	// metadata contains the object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of the SeccompProfile.
	// +required
	Spec SeccompProfileSpec `json:"spec,omitzero"`
	// status contains the observed state of the SeccompProfile.
	// +optional
	Status SeccompProfileStatus `json:"status,omitempty"`
}

func (sp *SeccompProfile) GetStatusBase() *profilebase.StatusBase {
	return &sp.Status.StatusBase
}

func (sp *SeccompProfile) DeepCopyToStatusBaseIf() profilebase.StatusBaseUser {
	return sp.DeepCopy()
}

func (sp *SeccompProfile) SetImplementationStatus() {
	profilePath := sp.GetProfilePath()
	sp.Status.LocalhostProfile = strings.TrimPrefix(profilePath, config.KubeletSeccompRootPath()+"/")
}

func (sp *SeccompProfile) GetProfileFile() string {
	pfile := sp.GetName()
	if !strings.HasSuffix(pfile, ExtJSON) {
		pfile = sp.GetName() + ExtJSON
	}

	return pfile
}

func (sp *SeccompProfile) GetProfilePath() string {
	pfile := sp.GetProfileFile()

	return path.Join(
		config.ProfilesRootPath(),
		filepath.Base(sp.GetNamespace()),
		filepath.Base(pfile),
	)
}

func (sp *SeccompProfile) GetProfileOperatorPath() string {
	pfile := sp.GetProfileFile()

	return path.Join(
		config.OperatorRoot,
		filepath.Base(sp.GetNamespace()),
		filepath.Base(pfile),
	)
}

func (sp *SeccompProfile) ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recording string,
) ([]metav1.Object, error) {
	return profilebase.ListProfilesByRecording(ctx, cli, recording, sp.Namespace, &SeccompProfileList{})
}

func (sp *SeccompProfile) IsPartial() bool {
	return profilebase.IsPartial(sp)
}

func (sp *SeccompProfile) IsDisabled() bool {
	return profilebase.IsDisabled(&sp.Spec.SpecBase)
}

func (sp *SeccompProfile) IsReconcilable() bool {
	return profilebase.IsReconcilable(sp)
}

// +kubebuilder:object:root=true

// SeccompProfileList contains a list of SeccompProfile.
type SeccompProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SeccompProfile `json:"items"`
}

func init() { //nolint:gochecknoinits // required to init scheme
	SchemeBuilder.Register(&SeccompProfile{}, &SeccompProfileList{})
}
