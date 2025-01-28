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

	"github.com/containers/common/pkg/seccomp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// Ensure SeccompProfile implements the StatusBaseUser and SecurityProfileBase interfaces.
var (
	_ profilebase.StatusBaseUser      = &SeccompProfile{}
	_ profilebase.SecurityProfileBase = &SeccompProfile{}
)

const ExtJSON = ".json"

// SeccompProfileSpec defines the desired state of SeccompProfile.
type SeccompProfileSpec struct {
	// Common spec fields for all profiles.
	profilebase.SpecBase `json:",inline"`

	// BaseProfileName is the name of base profile (in the same namespace) that
	// will be unioned into this profile. Base profiles can be references as
	// remote OCI artifacts as well when prefixed with `oci://`.
	BaseProfileName string `json:"baseProfileName,omitempty"`

	// Properties from containers/common/pkg/seccomp.Seccomp type

	// the default action for seccomp
	//nolint:lll // required for kubebuilder
	// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG;SCMP_ACT_NOTIFY
	DefaultAction seccomp.Action `json:"defaultAction"`
	// the architecture used for system calls
	Architectures []Arch `json:"architectures,omitempty"`
	// path of UNIX domain socket to contact a seccomp agent for SCMP_ACT_NOTIFY
	ListenerPath string `json:"listenerPath,omitempty"`
	// opaque data to pass to the seccomp agent
	ListenerMetadata string `json:"listenerMetadata,omitempty"`
	// match a syscall in seccomp. While this property is OPTIONAL, some values
	// of defaultAction are not useful without syscalls entries. For example,
	// if defaultAction is SCMP_ACT_KILL and syscalls is empty or unset, the
	// kernel will kill the container process on its first syscall
	Syscalls []*Syscall `json:"syscalls,omitempty"`

	// Additional properties from OCI runtime spec

	// list of flags to use with seccomp(2)
	Flags []*Flag `json:"flags,omitempty"`
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
	// the names of the syscalls
	Names []string `json:"names"`
	// the action for seccomp rules
	//nolint:lll // required for kubebuilder
	// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG;SCMP_ACT_NOTIFY
	Action seccomp.Action `json:"action"`
	// the errno return code to use. Some actions like SCMP_ACT_ERRNO and
	// SCMP_ACT_TRACE allow to specify the errno code to return
	ErrnoRet uint `json:"errnoRet,omitempty"`
	// the specific syscall in seccomp
	// +kubebuilder:validation:MaxItems=6
	Args []*Arg `json:"args,omitempty"`
}

// Arg defines the specific syscall in seccomp.
type Arg struct {
	// the index for syscall arguments in seccomp
	// +kubebuilder:validation:Minimum=0
	Index uint `json:"index"`
	// the value for syscall arguments in seccomp
	// +kubebuilder:validation:Minimum=0
	Value uint64 `json:"value,omitempty"`
	// the value for syscall arguments in seccomp
	// +kubebuilder:validation:Minimum=0
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	// the operator for syscall arguments in seccomp
	//nolint:lll // required for kubebuilder
	// +kubebuilder:validation:Enum=SCMP_CMP_NE;SCMP_CMP_LT;SCMP_CMP_LE;SCMP_CMP_EQ;SCMP_CMP_GE;SCMP_CMP_GT;SCMP_CMP_MASKED_EQ
	Op seccomp.Operator `json:"op"`
}

// SeccompProfileStatus contains status of the deployed SeccompProfile.
type SeccompProfileStatus struct {
	profilebase.StatusBase `json:",inline"`
	Path                   string   `json:"path,omitempty"`
	ActiveWorkloads        []string `json:"activeWorkloads,omitempty"`
	// The path that should be provided to the `securityContext.seccompProfile.localhostProfile`
	// field of a Pod or container spec
	LocalhostProfile string `json:"localhostProfile,omitempty"`
}

// +kubebuilder:object:root=true

// SeccompProfile is a cluster level specification for a seccomp profile.
// See https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#seccomp
// +kubebuilder:resource:shortName=sp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="LocalhostProfile",type=string,priority=10,JSONPath=`.status.localhostProfile`
type SeccompProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SeccompProfileSpec   `json:"spec,omitempty"`
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
