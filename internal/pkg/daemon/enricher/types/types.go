/*
Copyright 2022 The Kubernetes Authors.

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

package types

import (
	"sync"
)

const (
	AuditTypeSeccomp  = "seccomp"
	AuditTypeSelinux  = "selinux"
	AuditTypeApparmor = "apparmor"
)

type AuditLine struct {
	AuditType string

	// common
	ProcessID   int
	TimestampID string

	// seccomp
	SystemCallID int32
	Executable   string

	// selinux
	Scontext string
	Tcontext string
	Tclass   string
	Perm     string

	// apparmor
	Apparmor  string
	Operation string
	// Profile is the name of the AppArmor profile under which the operation took place.
	Profile string
	// Name is what the operation wanted to access.
	Name string
	// ExtraInfo may contain addition information such as:
	// requested_mask, denied_mask, fsuid=65534, ouid and target.
	ExtraInfo string
}

type ContainerInfo struct {
	PodName       string
	ContainerName string
	Namespace     string
	ContainerID   string
	RecordProfile string
}

type ProcessInfo struct {
	Pid           int
	CmdLine       string
	Uid           uint32
	Gid           uint32
	Executable    string
	ExecRequestId *string
}
type LogBucket struct {
	SyscallIds    sync.Map
	ContainerInfo *ContainerInfo
	ProcessInfo   *ProcessInfo
	TimestampID   string
}

type EnricherLogLevel string

const (
	EnricherLogLevelMetadata EnricherLogLevel = "Metadata"
	EnricherLogLevelNone     EnricherLogLevel = "None"
)

// EnricherFilterOptions defines filtering options for enriched log lines.
type EnricherFilterOptions struct {
	// Priority is the order of rule application.
	// Lower numbers indicate higher priority.
	Priority int `json:"priority"`
	// Level specifies whether to log this line ("Metadata") or filter it out ("None").
	Level EnricherLogLevel `json:"level"`
	// MatchKeys is an array of keys to match against (e.g., ["namespace", "podName"]).
	// At least one item must be provided.
	MatchKeys []string `json:"matchKeys"`
	// MatchValues is an optional array of values to match against the matched keys.
	// If MatchValues is empty or not provided, the presence of the key is sufficient for a match.
	MatchValues *[]string `json:"matchValues,omitempty"`
}
