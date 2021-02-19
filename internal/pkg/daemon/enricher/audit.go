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

// Initially only seccomp logs  are supported
// type IDs are defined at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/audit.h
var auditRegex = regexp.MustCompile(`audit:.+type=1326.+audit\((.+)\).+pid=(\b\d+\b).+exe="(.+)".+syscall=(\b\d+\b).*`)

// minimum numbers of captures expected on a supported log line.
var minCapturesExpected = 5

// isAuditLine checks whether logLine is a supported audit line.
func isAuditLine(logLine string) bool {
	captures := auditRegex.FindStringSubmatch(logLine)

	return len(captures) > 1
}

// extractAuditLine extracts an auditline from logLine.
func extractAuditLine(logLine string) (*auditLine, error) {
	captures := auditRegex.FindStringSubmatch(logLine)
	if len(captures) < minCapturesExpected {
		return nil, errors.Wrap(errUnsupportedLogLine, logLine)
	}

	line := auditLine{}
	line.Type = "seccomp"
	line.TimestampID = captures[1]
	line.Executable = captures[3]
	if v, err := strconv.Atoi(captures[2]); err == nil {
		line.ProcessID = v
	}
	if v, err := strconv.Atoi(captures[4]); err == nil {
		line.SystemCallID = v
	}

	return &line, nil
}
