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

import specs "github.com/opencontainers/runtime-spec/specs-go"

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
	case specs.ActTrace:
		return levelTrace
	case specs.ActNotify:
		return levelNotify
	case specs.ActLog:
		return levelLog
	case specs.ActAllow:
		return levelAllow
	default:
		return levelUnknown
	}
}
