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

package enricher

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// type IDs are defined at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/audit.h
var (
	seccompLineRegex = regexp.MustCompile(
		`(type=SECCOMP|audit:.+type=1326).+audit\((.+)\).+pid=(\b\d+\b).+exe="(.+)".+syscall=(\b\d+\b).*`,
	)
	selinuxLineRegex = regexp.MustCompile(
		`type=AVC.+audit\((.+)\).+{ (.+) }.+pid=(\b\d+\b).*scontext=(.+) tcontext=(.+) tclass=(\b\w+\b).*`,
	)
	apparmorLineRegex = regexp.MustCompile(
		//nolint:lll // no need to wrap regex
		`(type=APPARMOR|audit:.+type=1400).+audit\((.+)\).+apparmor="(.+)".+operation="([a-zA-Z0-9\/\-\_]+)"\s(?:info.+)?profile="(.+)".+name="(.+)".+pid=(\b\d+\b).+comm="([a-zA-Z0-9\/\-\_]+)"\s?(.*)?`,
	)
)

var (
	minSeccompCapturesExpected  = 5
	minSelinuxCapturesExpected  = 7
	minAppArmorCapturesExpected = 9
)

// IsAuditLine checks whether logLine is a supported audit line.
func IsAuditLine(logLine string) bool {
	captures := seccompLineRegex.FindStringSubmatch(logLine)
	if len(captures) >= minSeccompCapturesExpected {
		return true
	}

	captures = selinuxLineRegex.FindStringSubmatch(logLine)
	if len(captures) >= minSelinuxCapturesExpected {
		return true
	}

	captures = apparmorLineRegex.FindStringSubmatch(logLine)

	return len(captures) >= minAppArmorCapturesExpected
}

// ExtractAuditLine extracts an auditline from logLine.
func ExtractAuditLine(logLine string) (*types.AuditLine, error) {
	if seccomp := extractSeccompLine(logLine); seccomp != nil {
		return seccomp, nil
	}

	if selinux := extractSelinuxLine(logLine); selinux != nil {
		return selinux, nil
	}

	if apparmor := extractApparmorLine(logLine); apparmor != nil {
		return apparmor, nil
	}

	return nil, fmt.Errorf("unsupported log line: %s", logLine)
}

func extractSeccompLine(logLine string) *types.AuditLine {
	captures := seccompLineRegex.FindStringSubmatch(logLine)
	if len(captures) < minSeccompCapturesExpected {
		return nil
	}

	line := types.AuditLine{}
	line.AuditType = types.AuditTypeSeccomp
	line.TimestampID = captures[2]
	line.Executable = captures[4]

	if v, err := strconv.Atoi(captures[3]); err == nil {
		line.ProcessID = v
	}

	const (
		base    = 10
		bitSize = 32
	)

	if v, err := strconv.ParseInt(captures[5], base, bitSize); err == nil {
		line.SystemCallID = int32(v)
	}

	return &line
}

func extractSelinuxLine(logLine string) *types.AuditLine {
	captures := selinuxLineRegex.FindStringSubmatch(logLine)
	if len(captures) < minSelinuxCapturesExpected {
		return nil
	}

	line := types.AuditLine{}
	line.AuditType = types.AuditTypeSelinux
	line.TimestampID = captures[1]
	line.Perm = captures[2]

	if v, err := strconv.Atoi(captures[3]); err == nil {
		line.ProcessID = v
	}

	line.Scontext = captures[4]
	line.Tcontext = captures[5]
	line.Tclass = captures[6]

	return &line
}

func extractApparmorLine(logLine string) *types.AuditLine {
	captures := apparmorLineRegex.FindStringSubmatch(logLine)
	if len(captures) < minAppArmorCapturesExpected {
		return nil
	}

	line := types.AuditLine{}
	line.AuditType = types.AuditTypeApparmor
	line.TimestampID = captures[2]
	line.Apparmor = captures[3]
	line.Operation = captures[4]
	line.Profile = captures[5]
	line.Name = captures[6]
	line.Executable = captures[8]

	if v, err := strconv.Atoi(captures[7]); err == nil {
		line.ProcessID = v
	}

	if len(captures) > minAppArmorCapturesExpected {
		line.ExtraInfo = strings.ReplaceAll(captures[9], "\"", "'")
	}

	return &line
}
