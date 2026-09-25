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

package auditsource

import (
	"encoding/hex"
	"errors"
	"fmt"
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
	a.file, err = tail.TailFile(filePath, common.LogTailConfig())
	if err != nil {
		return nil, err
	}

	log = make(chan *types.AuditLine, 32)

	go func() {
		for l := range a.file.Lines {
			line := l.Text
			a.logger.V(config.VerboseLevel).Info("Got line", "line", line)

			// ExtractAuditLine already reports non-matching lines, so
			// calling IsAuditLine first would just run the same regexes twice.
			auditLine, err := ExtractAuditLine(line)
			if err != nil {
				a.logger.V(config.VerboseLevel).Info("Not an audit line")

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

func (a *AuditdSource) Stop() {
	if a.file != nil {
		a.file.Cleanup()
	}
}

// type IDs are defined at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/audit.h
var (
	// auditHeaderRegex matches the record type and the timestamp of an audit
	// record, as written by auditd (type=SECCOMP msg=audit(...):) and by the
	// kernel to its log (audit: type=1326 audit(...):).
	auditHeaderRegex = regexp.MustCompile(`type=(\w+)\s+(?:msg=)?audit\(([^)]+)\):?`)

	selinuxPermsRegex = regexp.MustCompile(`\{\s*(.*?)\s*\}`)

	uidGidRegex = regexp.MustCompile(`.*?\suid=(\d+).*?\sgid=(\d+).*`)
)

// auditPrefilter is a cheap substring every supported audit line contains. It
// avoids parsing lines that cannot match.
const auditPrefilter = "audit("

// auditdEnrichmentSeparator separates the fields auditd interprets and appends
// to a record from the fields the kernel logged.
const auditdEnrichmentSeparator = '\x1d'

// untrustedFields are logged by the kernel with audit_log_untrustedstring:
// quoted if they are plain, and hex encoded without quotes if they contain a
// space, a quote or a control character.
var untrustedFields = map[string]bool{
	"comm":    true,
	"exe":     true,
	"name":    true,
	"path":    true,
	"profile": true,
	"target":  true,
	"peer":    true,
}

// auditField is a single key=value pair of an audit record.
type auditField struct {
	key string
	// value is unquoted and decoded.
	value string
	// raw is the value as it was logged.
	raw string
}

// auditFields are the key=value pairs of an audit record in the logged order.
type auditFields []auditField

func (f auditFields) get(key string) (string, bool) {
	for i := range f {
		if f[i].key == key {
			return f[i].value, true
		}
	}

	return "", false
}

// parseAuditFields tokenizes the key=value pairs of an audit record. Tokens
// without a `=` are skipped.
func parseAuditFields(record string) auditFields {
	var fields auditFields

	for i := 0; i < len(record); {
		// Skip separators.
		if record[i] == ' ' {
			i++

			continue
		}

		start := i
		for i < len(record) && record[i] != ' ' && record[i] != '=' {
			i++
		}

		if i >= len(record) || record[i] != '=' {
			// A token without a value, like "avc:" or "denied".
			continue
		}

		key := record[start:i]
		i++ // skip '='

		var raw, value string

		if i < len(record) && record[i] == '"' {
			closing := strings.IndexByte(record[i+1:], '"')
			if closing < 0 {
				raw, value = record[i:], record[i+1:]
			} else {
				raw, value = record[i:i+closing+2], record[i+1:i+1+closing]
			}

			i += len(raw)
		} else {
			valueStart := i
			for i < len(record) && record[i] != ' ' {
				i++
			}

			raw = record[valueStart:i]
			value = raw

			if untrustedFields[key] {
				value = decodeUntrusted(raw)
			}
		}

		fields = append(fields, auditField{key: key, value: value, raw: raw})
	}

	return fields
}

// decodeUntrusted decodes a hex encoded untrusted string. Values which are
// not valid hex are returned as they are.
func decodeUntrusted(raw string) string {
	if raw == "" || raw == "(null)" || len(raw)%2 != 0 {
		return raw
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return raw
	}

	return string(decoded)
}

// IsAuditLine checks whether logLine is a supported audit line.
func IsAuditLine(logLine string) bool {
	_, err := ExtractAuditLine(logLine)

	return err == nil
}

// ExtractAuditLine extracts an auditline from logLine.
func ExtractAuditLine(logLine string) (*types.AuditLine, error) {
	if !strings.Contains(logLine, auditPrefilter) {
		return nil, fmt.Errorf("unsupported log line: %s", logLine)
	}

	record := logLine
	if i := strings.IndexByte(record, auditdEnrichmentSeparator); i >= 0 {
		record = record[:i]
	}

	header := auditHeaderRegex.FindStringSubmatchIndex(record)
	if header == nil {
		return nil, fmt.Errorf("unsupported log line: %s", logLine)
	}

	recordType := record[header[2]:header[3]]
	timestamp := record[header[4]:header[5]]
	body := record[header[1]:]
	fields := parseAuditFields(body)

	var line *types.AuditLine

	switch recordType {
	case "SECCOMP", "1326":
		line = extractSeccompLine(fields)
	case "AVC", "1400", "APPARMOR", "APPARMOR_DENIED", "APPARMOR_ALLOWED",
		"APPARMOR_AUDIT", "1503", "1502", "1501":
		// AppArmor records share the AVC type with SELinux.
		if _, ok := fields.get("apparmor"); ok {
			line = extractApparmorLine(fields)
		} else {
			line = extractSelinuxLine(body, fields)
		}
	}

	if line == nil {
		return nil, fmt.Errorf("unsupported log line: %s", logLine)
	}

	line.TimestampID = timestamp

	return line, nil
}

func extractSeccompLine(fields auditFields) *types.AuditLine {
	pid, okPid := fields.get("pid")
	syscall, okSyscall := fields.get("syscall")

	if !okPid || !okSyscall {
		return nil
	}

	syscallID, err := strconv.ParseInt(syscall, 10, 32)
	if err != nil {
		return nil
	}

	exe, _ := fields.get("exe")
	arch, _ := fields.get("arch")

	line := types.AuditLine{
		AuditType:    types.AuditTypeSeccomp,
		Executable:   exe,
		SystemCallID: int32(syscallID),
		Arch:         arch,
	}

	if !extractProcessID(&line, pid) {
		return nil
	}

	return &line
}

// extractProcessID sets the process ID of line and reports whether it is a
// valid one.
func extractProcessID(line *types.AuditLine, capturedProcessID string) bool {
	pid, err := strconv.Atoi(capturedProcessID)
	if err != nil {
		return false
	}

	line.ProcessID = pid

	return true
}

func extractSelinuxLine(body string, fields auditFields) *types.AuditLine {
	perms := selinuxPermsRegex.FindStringSubmatch(body)
	pid, okPid := fields.get("pid")
	scontext, okScontext := fields.get("scontext")
	tcontext, okTcontext := fields.get("tcontext")
	tclass, okTclass := fields.get("tclass")

	if perms == nil || !okPid || !okScontext || !okTcontext || !okTclass {
		return nil
	}

	line := types.AuditLine{
		AuditType: types.AuditTypeSelinux,
		Perm:      perms[1],
		Scontext:  scontext,
		Tcontext:  tcontext,
		Tclass:    tclass,
	}

	if !extractProcessID(&line, pid) {
		return nil
	}

	return &line
}

// apparmorKnownFields are stored in dedicated fields of the audit line, every
// other field goes into its extra info.
var apparmorKnownFields = map[string]bool{
	"apparmor":  true,
	"operation": true,
	"profile":   true,
	"name":      true,
	"pid":       true,
	"comm":      true,
}

// extractApparmorLine extracts file, capability and network records alike:
// only the latter carry no name, they log capname or the socket family
// instead, which end up in the extra info.
func extractApparmorLine(fields auditFields) *types.AuditLine {
	apparmor, _ := fields.get("apparmor")
	operation, okOperation := fields.get("operation")
	pid, okPid := fields.get("pid")

	if !okOperation || !okPid {
		return nil
	}

	profile, _ := fields.get("profile")
	name, _ := fields.get("name")
	comm, _ := fields.get("comm")

	line := types.AuditLine{
		AuditType:  types.AuditTypeApparmor,
		Apparmor:   apparmor,
		Operation:  operation,
		Profile:    profile,
		Name:       name,
		Executable: comm,
	}

	if !extractProcessID(&line, pid) {
		return nil
	}

	// Only the fields logged after the process are extra info, the ones
	// before describe the record itself.
	extra := []string{}
	afterComm := false

	for _, field := range fields {
		if field.key == "comm" {
			afterComm = true

			continue
		}

		if !afterComm || apparmorKnownFields[field.key] {
			continue
		}

		extra = append(extra, field.key+"="+strings.ReplaceAll(field.raw, "\"", "'"))
	}

	line.ExtraInfo = strings.Join(extra, " ")

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
