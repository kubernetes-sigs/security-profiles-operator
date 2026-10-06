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
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/tailer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

type AuditdSource struct {
	logger logr.Logger
	// path is the file to follow, the audit log or syslog if it is empty.
	path string
	file *tailer.Tailer
	// done is closed by Stop, so that the forwarding goroutine does not wait
	// for a consumer which is gone.
	done     chan struct{}
	stopOnce sync.Once
}

func NewAuditdSource(logger logr.Logger) *AuditdSource {
	return &AuditdSource{
		logger: logger,
		done:   make(chan struct{}),
	}
}

func (a *AuditdSource) StartTail() (log chan *types.AuditLine, err error) {
	filePath := a.path
	if filePath == "" {
		// Use auditd logs as main source or syslog as fallback.
		filePath = common.LogFilePath()
	}

	// If the file does not exist, then the tailer waits for it to appear.
	a.file, err = tailer.Follow(filePath, tailer.Config{})
	if err != nil {
		return nil, err
	}

	log = make(chan *types.AuditLine, 32)

	go a.forward(a.file.Lines(), log)

	return log, nil
}

// forward sends the audit lines of the log lines to log until the lines end
// or the source is stopped.
func (a *AuditdSource) forward(lines <-chan string, log chan<- *types.AuditLine) {
	defer close(log)

	for {
		var (
			line string
			ok   bool
		)

		select {
		case line, ok = <-lines:
			if !ok {
				return
			}
		case <-a.done:
			return
		}

		a.logger.V(config.VerboseLevel).Info("Got line", "line", line)

		// ExtractAuditLine already reports non-matching lines, so calling
		// IsAuditLine first would just run the same regexes twice.
		auditLine, err := ExtractAuditLine(line)
		if err != nil {
			a.logger.V(config.VerboseLevel).Info("Not an audit line")

			continue
		}

		select {
		case log <- auditLine:
		case <-a.done:
			return
		}
	}
}

func (a *AuditdSource) TailErr() error {
	if a.file == nil {
		return nil
	}

	return a.file.Err()
}

func (a *AuditdSource) Stop() {
	a.stopOnce.Do(func() {
		close(a.done)
	})

	if a.file != nil {
		a.file.Stop()
	}
}

// type IDs are defined at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/audit.h
var (
	// auditHeaderRegex matches the record type and the timestamp of an audit
	// record, as written by auditd (type=SECCOMP msg=audit(...):) and by the
	// kernel to its log (audit: type=1326 audit(...):).
	auditHeaderRegex = regexp.MustCompile(`type=(\w+)\s+(?:msg=)?audit\(([^)]+)\):?`)

	selinuxPermsRegex = regexp.MustCompile(`\{\s*(.*?)\s*\}`)
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

// ErrUnsupportedLine is returned by ExtractAuditLine for a line which is no
// supported audit record. It carries no details, since most lines of the log
// are no audit records and the callers skip them.
var ErrUnsupportedLine = errors.New("unsupported log line")

// IsAuditLine checks whether logLine is a supported audit line.
func IsAuditLine(logLine string) bool {
	_, err := ExtractAuditLine(logLine)

	return err == nil
}

// ExtractAuditLine extracts an auditline from logLine. It returns
// ErrUnsupportedLine for a line which is no supported audit record. The fields
// of a record are only parsed for the supported record types.
func ExtractAuditLine(logLine string) (*types.AuditLine, error) {
	if !strings.Contains(logLine, auditPrefilter) {
		return nil, ErrUnsupportedLine
	}

	record := logLine
	if i := strings.IndexByte(record, auditdEnrichmentSeparator); i >= 0 {
		record = record[:i]
	}

	header := auditHeaderRegex.FindStringSubmatchIndex(record)
	if header == nil {
		return nil, ErrUnsupportedLine
	}

	var extract func(body string, fields auditFields) *types.AuditLine

	switch record[header[2]:header[3]] {
	case "SECCOMP", "1326":
		extract = func(_ string, fields auditFields) *types.AuditLine {
			return extractSeccompLine(fields)
		}
	case "AVC", "1400", "APPARMOR", "APPARMOR_DENIED", "APPARMOR_ALLOWED",
		"APPARMOR_AUDIT", "1503", "1502", "1501":
		extract = extractAvcLine
	default:
		return nil, ErrUnsupportedLine
	}

	body := record[header[1]:]

	line := extract(body, parseAuditFields(body))
	if line == nil {
		return nil, ErrUnsupportedLine
	}

	line.TimestampID = record[header[4]:header[5]]

	return line, nil
}

// extractAvcLine extracts an AppArmor or SELinux record. AppArmor records
// share the AVC type with SELinux.
func extractAvcLine(body string, fields auditFields) *types.AuditLine {
	if _, ok := fields.get("apparmor"); ok {
		return extractApparmorLine(fields)
	}

	return extractSelinuxLine(body, fields)
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
		Uid:          extractID(fields, "uid"),
		Gid:          extractID(fields, "gid"),
	}

	if !extractProcessID(&line, pid) {
		return nil
	}

	return &line
}

// extractID returns the numeric ID field, or nil if the record does not carry
// a valid one.
func extractID(fields auditFields, key string) *uint32 {
	value, ok := fields.get(key)
	if !ok {
		return nil
	}

	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return nil
	}

	result := uint32(id)

	return &result
}

// extractProcessID sets the process ID of line and reports whether it is a
// valid one.
func extractProcessID(line *types.AuditLine, capturedProcessID string) bool {
	// A PID is positive and fits into a pid_t, which rejects values like
	// pid=-1 or pid=+1.
	pid, err := strconv.ParseUint(capturedProcessID, 10, 31)
	if err != nil || pid == 0 {
		return false
	}

	line.ProcessID = int(pid)

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
