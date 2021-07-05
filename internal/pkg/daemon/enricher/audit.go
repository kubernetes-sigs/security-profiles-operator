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
	"regexp"
	"strconv"

	"github.com/pkg/errors"
)

// type IDs are defined at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/audit.h
var (
	seccompLineRegex = regexp.MustCompile(
		`(type=SECCOMP|audit:.+type=1326).+audit\((.+)\).+pid=(\b\d+\b).+exe="(.+)".+syscall=(\b\d+\b).*`,
	)
	selinuxLineRegex = regexp.MustCompile(`type=AVC.+audit\((.+)\).+pid=(\b\d+\b).*`)
)

var (
	minSeccompCapturesExpected = 5
	minSelinuxCapturesExpected = 3
)

// isAuditLine checks whether logLine is a supported audit line.
func isAuditLine(logLine string) bool {
	captures := seccompLineRegex.FindStringSubmatch(logLine)
	if len(captures) >= minSeccompCapturesExpected {
		return true
	}

	captures = selinuxLineRegex.FindStringSubmatch(logLine)
	return len(captures) >= minSelinuxCapturesExpected
}

// extractAuditLine extracts an auditline from logLine.
func extractAuditLine(logLine string) (*auditLine, error) {
	if seccomp := extractSeccompLine(logLine); seccomp != nil {
		return seccomp, nil
	}

	if selinux := extractSelinuxLine(logLine); selinux != nil {
		return selinux, nil
	}

	return nil, errors.Errorf("unsupported log line: %s", logLine)
}

func extractSeccompLine(logLine string) *auditLine {
	captures := seccompLineRegex.FindStringSubmatch(logLine)
	if len(captures) < minSeccompCapturesExpected {
		return nil
	}

	line := auditLine{}
	line.type_ = auditTypeSeccomp
	line.timestampID = captures[2]
	line.executable = captures[4]
	if v, err := strconv.Atoi(captures[3]); err == nil {
		line.processID = v
	}
	if v, err := strconv.Atoi(captures[5]); err == nil {
		line.systemCallID = v
	}

	return &line
}

func extractSelinuxLine(logLine string) *auditLine {
	captures := selinuxLineRegex.FindStringSubmatch(logLine)
	if len(captures) < minSelinuxCapturesExpected {
		return nil
	}

	line := auditLine{}
	line.type_ = auditTypeSelinux
	line.timestampID = captures[1]
	if v, err := strconv.Atoi(captures[2]); err == nil {
		line.processID = v
	}

	return &line
}
