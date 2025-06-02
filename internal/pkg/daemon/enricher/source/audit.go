/*
Copyright 2025 The Kubernetes Authors.

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

package source

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/nxadm/tail"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

type AuditdSource struct {
	logger logr.Logger
	file   *tail.Tail
}

func NewAuditdSource(logger logr.Logger) *AuditdSource {
	return &AuditdSource{
		logger: logger,
	}
}

func (a *AuditdSource) StartTail() (log chan *types.AuditLine, err error) {
	// Use auditd logs as main source or syslog as fallback.
	filePath := common.LogFilePath()

	// If the file does not exist, then tail will wait for it to appear
	a.file, err = tail.TailFile(filePath, tail.Config{
		ReOpen: true,
		Follow: true,
		Location: &tail.SeekInfo{
			Offset: 0,
			Whence: io.SeekEnd,
		},
	})
	if err != nil {
		return nil, err
	}

	log = make(chan *types.AuditLine, 32)
	go func() {
		for l := range a.file.Lines {
			line := l.Text
			a.logger.V(config.VerboseLevel).Info("Got line: " + line)

			if !IsAuditLine(line) {
				a.logger.V(config.VerboseLevel).Info("Not an audit line")

				continue
			}

			auditLine, err := ExtractAuditLine(line)
			if err != nil {
				a.logger.Error(err, "extract audit line")

				continue
			}

			log <- auditLine
		}

		close(log)
	}()

	return log, nil
}

func (a *AuditdSource) TailErr() error {
	return a.file.Err()
}

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

	uidGidRegex = regexp.MustCompile(`.*\suid=([\d+]).*\sgid=([\d+]).*`)
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

	line := types.AuditLine{
		AuditType:   types.AuditTypeSeccomp,
		TimestampID: captures[2],
		Executable:  captures[4],
	}

	extractProcessId(&line, captures[3])

	if syscallID, err := strconv.ParseInt(captures[5], 10, 32); err == nil {
		line.SystemCallID = int32(syscallID)
	}

	return &line
}

func extractProcessId(line *types.AuditLine, capturedProcessID string) {
	if pid, err := strconv.Atoi(capturedProcessID); err == nil {
		line.ProcessID = pid
	}
}

func extractSelinuxLine(logLine string) *types.AuditLine {
	captures := selinuxLineRegex.FindStringSubmatch(logLine)
	if len(captures) < minSelinuxCapturesExpected {
		return nil
	}

	line := types.AuditLine{
		AuditType:   types.AuditTypeSelinux,
		TimestampID: captures[1],
		Perm:        captures[2],
	}

	extractProcessId(&line, captures[3])

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

	line := types.AuditLine{
		AuditType:   types.AuditTypeApparmor,
		TimestampID: captures[2],
		Apparmor:    captures[3],
		Operation:   captures[4],
		Profile:     captures[5],
		Name:        captures[6],
		Executable:  captures[8],
	}

	extractProcessId(&line, captures[7])

	if len(captures) > minAppArmorCapturesExpected {
		line.ExtraInfo = strings.ReplaceAll(captures[9], "\"", "'")
	}

	return &line
}

func GetUidGid(auditLine string) (uid, gid uint32, err error) {
	captures := uidGidRegex.FindStringSubmatch(auditLine)
	if len(captures) < 2 {
		return 0, 0, errors.New("uid and gid are missing")
	}

	uid64, errUid := strconv.ParseUint(captures[1], 10, 32)
	if errUid != nil {
		return 0, 0, errUid
	}

	gid64, errGid := strconv.ParseUint(captures[2], 10, 32)
	if errGid != nil {
		return 0, 0, errGid
	}

	return uint32(uid64), uint32(gid64), nil
}
