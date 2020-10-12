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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SeccompProfileSpec defines the desired state of SeccompProfile.
type SeccompProfileSpec struct {
	// the type of application workload for which the profile is targeted. Will be a subdirectory in the profile path on disk.
	//nolint:lll
	TargetWorkload string `json:"targetWorkload"`

	// Properties from containers/common/pkg/seccomp.Seccomp type

	// the default action for seccomp
	//nolint:lll
	// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG
	DefaultAction seccomp.Action `json:"defaultAction"`
	// the architecture used for system calls
	Architectures []*Arch `json:"architectures,omitempty"`
	// match a syscall in seccomp. While this property is OPTIONAL, some values
	// of defaultAction are not useful without syscalls entries. For example,
	// if defaultAction is SCMP_ACT_KILL and syscalls is empty or unset, the
	// kernel will kill the container process on its first syscall
	Syscalls []*Syscall `json:"syscalls,omitempty"`

	// Additional properties from OCI runtime spec

	// list of flags to use with seccomp(2)
	Flags []*Flag `json:"flags,omitempty"`
}

//nolint:lll
// +kubebuilder:validation:Enum=SCMP_ARCH_X86;SCMP_ARCH_X86_64;SCMP_ARCH_X32;SCMP_ARCH_ARM;SCMP_ARCH_AARCH64;SCMP_ARCH_MIPS;SCMP_ARCH_MIPS64;SCMP_ARCH_MIPS64N32;SCMP_ARCH_MIPSEL;SCMP_ARCH_MIPSEL64;SCMP_ARCH_MIPSEL64N32;SCMP_ARCH_PPC;SCMP_ARCH_PPC64;SCMP_ARCH_PPC64LE;SCMP_ARCH_S390;SCMP_ARCH_S390X;SCMP_ARCH_PARISC;SCMP_ARCH_PARISC64;SCMP_ARCH_RISCV64
type Arch string

// +kubebuilder:validation:Enum=SECCOMP_FILTER_FLAG_TSYNC;SECCOMP_FILTER_FLAG_LOG;SECCOMP_FILTER_FLAG_SPEC_ALLOW
type Flag string

// Syscall defines a syscall in seccomp.
type Syscall struct {
	// the names of the syscalls
	Names []string `json:"names"`
	// the action for seccomp rules
	//nolint:lll
	// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG
	Action seccomp.Action `json:"action"`
	// the errno return code to use. Some actions like SCMP_ACT_ERRNO and
	// SCMP_ACT_TRACE allow to specify the errno code to return
	ErrnoRet string `json:"errnoRet,omitempty"`
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
	//nolint:lll
	// +kubebuilder:validation:Enum=SCMP_CMP_NE;SCMP_CMP_LT;SCMP_CMP_LE;SCMP_CMP_EQ;SCMP_CMP_GE;SCMP_CMP_GT;SCMP_CMP_MASKED_EQ
	Op seccomp.Operator `json:"op"`
}

// SeccompProfileStatus contains the host path of the deployed SeccompProfile.
type SeccompProfileStatus struct {
	Path string `json:"path,omitempty"`
}

// +kubebuilder:object:root=true

// SeccompProfile is a cluster level specification for a seccomp profile.
// See https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md#seccomp
// +kubebuilder:resource:shortName=sp
// +kubebuilder:subresource:status
type SeccompProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SeccompProfileSpec   `json:"spec,omitempty"`
	Status SeccompProfileStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SeccompProfileList contains a list of SeccompProfile.
type SeccompProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SeccompProfile `json:"items"`
}

func init() { //nolint:gochecknoinits
	SchemeBuilder.Register(&SeccompProfile{}, &SeccompProfileList{})
}
