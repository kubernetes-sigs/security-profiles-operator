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

// Package seccomp provides merge operations for seccomp profiles.
package seccomp

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/merge"
)

// defaultErrno is the errno runc and crun apply for SCMP_ACT_ERRNO and
// SCMP_ACT_TRACE when errnoRet is unset: EPERM.
const defaultErrno uint = 1

// Restrictiveness levels, ordered from most restrictive (kill) to least
// (allow). Notify sits between Errno and Trace: it blocks the syscall pending
// a supervisor decision, making it more restrictive than Trace (which traps to
// a ptrace tracer) but less restrictive than Errno (which fails outright
// without supervisor intervention).
const (
	levelKillProcess = iota
	levelKillThread
	levelTrap
	levelErrno
	levelNotify
	levelTrace
	levelLog
	levelAllow
)

const levelUnknown = -1

// MoreRestrictive returns the more restrictive of two seccomp actions.
// If an action is unknown, it is treated as the most restrictive (kill).
func MoreRestrictive(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction {
	firstLevel := restrictiveness(first)
	secondLevel := restrictiveness(second)

	if firstLevel <= secondLevel {
		return first
	}

	return second
}

// LessRestrictive returns the less restrictive of two seccomp actions.
// If an action is unknown, it is treated as the most restrictive (kill).
func LessRestrictive(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction {
	firstLevel := restrictiveness(first)
	secondLevel := restrictiveness(second)

	if firstLevel >= secondLevel {
		return first
	}

	return second
}

func actionsEquivalent(a, b specs.LinuxSeccompAction) bool {
	return restrictiveness(a) == restrictiveness(b)
}

func restrictiveness(action specs.LinuxSeccompAction) int {
	switch action {
	case specs.ActKillProcess:
		return levelKillProcess
	case specs.ActKill, specs.ActKillThread:
		return levelKillThread
	case specs.ActTrap:
		return levelTrap
	case specs.ActErrno:
		return levelErrno
	case specs.ActNotify:
		return levelNotify
	case specs.ActTrace:
		return levelTrace
	case specs.ActLog:
		return levelLog
	case specs.ActAllow:
		return levelAllow
	default:
		return levelUnknown
	}
}

// errnoSignificant reports whether ErrnoRet changes the runtime effect of an
// action. Runtimes only pass the errno value along for ERRNO and TRACE.
func errnoSignificant(action specs.LinuxSeccompAction) bool {
	return action == specs.ActErrno || action == specs.ActTrace
}

// runtimeErrno returns the errno a runtime applies for an action: the
// explicit value or EPERM for ERRNO and TRACE, and nil for every other
// action, which ignores errnoRet. Clauses carry this form so that entries
// differing only in how they spell EPERM compare equal.
func runtimeErrno(action specs.LinuxSeccompAction, ret *uint) *uint {
	if !errnoSignificant(action) {
		return nil
	}

	if ret == nil {
		val := defaultErrno

		return &val
	}

	return merge.ClonePtr(ret)
}

// outputErrno returns the serialized form of an errno: nil when the runtime
// ignores it or would apply EPERM anyway, so that merge results spell the
// default the way most profiles do.
func outputErrno(action specs.LinuxSeccompAction, ret *uint) *uint {
	if !errnoSignificant(action) || ret == nil || *ret == defaultErrno {
		return nil
	}

	return merge.ClonePtr(ret)
}
