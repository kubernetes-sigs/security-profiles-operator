/*
Copyright 2026 The Kubernetes Authors.

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

package seccomp

// +kubebuilder:validation:Enum=SCMP_ACT_KILL;SCMP_ACT_KILL_PROCESS;SCMP_ACT_KILL_THREAD;SCMP_ACT_TRAP;SCMP_ACT_ERRNO;SCMP_ACT_TRACE;SCMP_ACT_ALLOW;SCMP_ACT_LOG;SCMP_ACT_NOTIFY
//
//nolint:lll // required for kubebuilder
type Action string

const (
	ActKill        Action = "SCMP_ACT_KILL"
	ActKillProcess Action = "SCMP_ACT_KILL_PROCESS"
	ActKillThread  Action = "SCMP_ACT_KILL_THREAD"
	ActTrap        Action = "SCMP_ACT_TRAP"
	ActErrno       Action = "SCMP_ACT_ERRNO"
	ActTrace       Action = "SCMP_ACT_TRACE"
	ActAllow       Action = "SCMP_ACT_ALLOW"
	ActLog         Action = "SCMP_ACT_LOG"
	ActNotify      Action = "SCMP_ACT_NOTIFY"
)

// +kubebuilder:validation:Enum=SCMP_CMP_NE;SCMP_CMP_LT;SCMP_CMP_LE;SCMP_CMP_EQ;SCMP_CMP_GE;SCMP_CMP_GT;SCMP_CMP_MASKED_EQ
//
//nolint:lll // required for kubebuilder
type Operator string

const (
	OpNotEqual     Operator = "SCMP_CMP_NE"
	OpLessThan     Operator = "SCMP_CMP_LT"
	OpLessEqual    Operator = "SCMP_CMP_LE"
	OpEqualTo      Operator = "SCMP_CMP_EQ"
	OpGreaterEqual Operator = "SCMP_CMP_GE"
	OpGreaterThan  Operator = "SCMP_CMP_GT"
	OpMaskedEqual  Operator = "SCMP_CMP_MASKED_EQ"
)
