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
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// fuzzAuditLines are the log lines of the audit test tables, covering every
// supported record type and both the auditd and the kernel log format.
var fuzzAuditLines = []string{
	`audit: type=1326 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 ` +
		`pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ` +
		`ip=0x7f61a81c5923 code=0x7ffc0000`,
	`Jul  8 10:31:23 ubuntu2004 kernel: [  270.853767] audit: type=1326 audit(1625740283.502:574): ` +
		`auid=4294967295 uid=0 gid=0 ses=4294967295 pid=4709 comm="sh" exe="/bin/busybox" sig=0 ` +
		`arch=c000003e syscall=13 compat=0 ip=0x7f3c012e467b code=0x7ffc0000`,
	`type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 ses=4294967295 ` +
		`subj=system_u:system_r:spc_t:s0:c284,c594 pid=2039886 comm="ls" exe="/bin/ls" sig=0 ` +
		`arch=c000003e syscall=3 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000` + "\x1d" +
		`AUID="unset" UID="root" GID="root" ARCH=x86_64 SYSCALL=close`,
	`audit: type=1016 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 pid=615549 syscall=1`,
	`type=1326 syscall=1`,
	`type=AVC msg=audit(1613173578.156:2945): avc:  denied  { read } for  pid=75593 ` +
		`comm="security-profil" name="token" dev="tmpfs" ino=612459 ` +
		`scontext=system_u:system_r:container_t:s0:c4,c808 tcontext=system_u:object_r:var_lib_t:s0 ` +
		`tclass=lnk_file permissive=0`,
	`type=AVC msg=audit(1666691794.882:1434): avc:  denied  { read write open } for  pid=94509 ` +
		`comm="aide" path="/hostroot/etc/kubernetes/aide.log.new" dev="nvme0n1p4" ino=167774224 ` +
		`scontext=system_u:system_r:selinuxrecording.process:s0:c218,c875 ` +
		`tcontext=system_u:object_r:kubernetes_file_t:s0 tclass=file permissive=1`,
	`audit: type=1400 audit(1668191154.949:64): apparmor="DENIED" operation="exec" ` +
		`profile="profile-name" name="/usr/local/bin/sample-app" pid=4166 comm="tini" ` +
		`requested_mask="x" denied_mask="x" fsuid=65534 ouid=0`,
	`type=SECCOMP msg=audit(1613596317.899:6462): auid=4294967295 uid=0 gid=0 ses=4294967295 ` +
		`pid=2039887 comm=6D7920617070 exe=2F6F70742F6D79206170702F62696E sig=0 arch=c000003e ` +
		`syscall=2 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000`,
	`audit: type=1400 audit(1668191154.949:65): apparmor="DENIED" operation="open" ` +
		`profile="profile-name" name="/etc/shadow" pid=4167 comm=4332204361636865 ` +
		`requested_mask="r" denied_mask="r" fsuid=0 ouid=0`,
	`type=AVC msg=audit(1668191154.949:66): apparmor="DENIED" operation="capable" class="cap" ` +
		`profile="profile-name" pid=4168 comm="ping" capability=13  capname="net_raw"`,
	`audit: type=1400 audit(1668191154.949:67): apparmor="DENIED" operation="create" class="net" ` +
		`profile="profile-name" pid=4169 comm="curl" family="inet" sock_type="raw" protocol=1 ` +
		`requested_mask="create" denied_mask="create"`,
	`type=SECCOMP msg=audit(1613596317.899:6464): pid=7 comm="a" exe="/a" arch=16 syscall=102 compat=0`,
	`type=SECCOMP msg=audit(1613596317.899:6461): pid=2039886 comm="ls" exe="/bin/ls"`,
	`type=SECCOMP msg=audit(1:2): pid=1 syscall=1 exe="unterminated`,
	`type=SECCOMP msg=audit(1:2): =x pid= syscall=`,
	``,
}

// FuzzExtractAuditLine feeds arbitrary log lines into the parser of audit
// records. It must never panic, and an accepted line has to be consistent
// with the record it was derived from.
func FuzzExtractAuditLine(f *testing.F) {
	for _, seed := range fuzzAuditLines {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, logLine string) {
		line, err := ExtractAuditLine(logLine)
		require.Equal(t, err == nil, IsAuditLine(logLine))

		if err != nil {
			require.Nil(t, line)

			return
		}

		require.NotNil(t, line)
		require.Contains(t, logLine, auditPrefilter)

		// The timestamp is the content of the audit(...) header, which is
		// part of the record before any auditd enrichment.
		record, _, _ := strings.Cut(logLine, string(auditdEnrichmentSeparator))

		require.NotEmpty(t, line.TimestampID)
		require.NotContains(t, line.TimestampID, ")")
		require.Contains(t, record, "audit("+line.TimestampID+")")

		requireAuditLineFields(t, record, line)

		again, err := ExtractAuditLine(logLine)
		require.NoError(t, err)
		require.Equal(t, line, again)
	})
}

// requireAuditLineFields verifies the fields of an accepted audit line
// against the key=value pairs of its record.
func requireAuditLineFields(t *testing.T, record string, line *types.AuditLine) {
	t.Helper()

	header := auditHeaderRegex.FindStringSubmatchIndex(record)
	require.NotNil(t, header)

	fields := parseAuditFields(record[header[1]:])

	pid, ok := fields.get("pid")
	require.True(t, ok)

	parsedPid, err := strconv.Atoi(pid)
	require.NoError(t, err)
	require.Equal(t, parsedPid, line.ProcessID)

	switch line.AuditType {
	case types.AuditTypeSeccomp:
		syscall, ok := fields.get("syscall")
		require.True(t, ok)

		syscallID, err := strconv.ParseInt(syscall, 10, 32)
		require.NoError(t, err)
		require.Equal(t, int32(syscallID), line.SystemCallID)

		requireID(t, fields, "uid", line.Uid)
		requireID(t, fields, "gid", line.Gid)
	case types.AuditTypeSelinux:
		require.NotContains(t, line.Perm, "}")

		for _, key := range []string{"scontext", "tcontext", "tclass"} {
			_, ok := fields.get(key)
			require.True(t, ok, key)
		}
	case types.AuditTypeApparmor:
		operation, ok := fields.get("operation")
		require.True(t, ok)
		require.Equal(t, operation, line.Operation)
	default:
		require.Failf(t, "unexpected audit type", "%q", line.AuditType)
	}
}

func requireID(t *testing.T, fields auditFields, key string, id *uint32) {
	t.Helper()

	value, ok := fields.get(key)
	if !ok {
		require.Nil(t, id)

		return
	}

	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		require.Nil(t, id)

		return
	}

	require.NotNil(t, id)
	require.Equal(t, uint32(parsed), *id)
}

// FuzzParseAuditFields verifies that the tokenizer of audit records never
// panics, keeps the logged order and derives every value from its raw form.
func FuzzParseAuditFields(f *testing.F) {
	for _, seed := range fuzzAuditLines {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, record string) {
		fields := parseAuditFields(record)

		offset := 0

		for _, field := range fields {
			require.NotContains(t, field.key, " ")
			require.NotContains(t, field.key, "=")

			// Every field is logged as key=raw, after the previous one.
			pos := strings.Index(record[offset:], field.key+"="+field.raw)
			require.GreaterOrEqual(
				t, pos, 0, "field %q=%q not found in order", field.key, field.raw,
			)

			offset += pos + len(field.key) + 1 + len(field.raw)

			switch {
			case strings.HasPrefix(field.raw, `"`):
				require.Equal(t, strings.TrimSuffix(field.raw[1:], `"`), field.value)
				require.NotContains(t, field.value, `"`)
			case untrustedFields[field.key]:
				require.NotContains(t, field.raw, " ")
				require.Equal(t, decodeUntrusted(field.raw), field.value)
			default:
				require.NotContains(t, field.raw, " ")
				require.Equal(t, field.raw, field.value)
			}
		}
	})
}

// FuzzParseBpfAuditEvent feeds arbitrary ring buffer events into the decoding
// of the AppArmor enricher events.
func FuzzParseBpfAuditEvent(f *testing.F) {
	f.Add(bpfAuditEvent(4026531840, 4, 0, "open", "cat", "/etc/shadow"))
	f.Add(bpfAuditEvent(1, 2, 1, "exec", "sh", "/bin/ls"))
	f.Add(bpfAuditEvent(0, 0, 0, "", "", ""))
	f.Add(bpfAuditEvent(0, 0, 0, "only", "two"))
	f.Add(bytes.Repeat([]byte{0xff}, bpfAuditHeaderSize+1))
	f.Add([]byte{})

	now := time.UnixMilli(1700000000042)

	f.Fuzz(func(t *testing.T, raw []byte) {
		line, mntns, err := parseBpfAuditEvent(raw, now)
		if err != nil {
			require.ErrorIs(t, err, errInvalidBpfAuditEvent)
			require.Nil(t, line)
			require.Zero(t, mntns)

			return
		}

		require.NotNil(t, line)
		require.Greater(t, len(raw), bpfAuditHeaderSize)
		require.Equal(t, binary.LittleEndian.Uint32(raw[0:4]), mntns)
		require.GreaterOrEqual(t, line.ProcessID, 0)
		require.Equal(t, int(binary.LittleEndian.Uint32(raw[4:8])), line.ProcessID)
		require.Equal(t, types.AuditTypeApparmor, line.AuditType)
		require.Equal(t, "1700000000.042", line.TimestampID)
		require.Equal(t,
			"request:"+strconv.FormatUint(uint64(binary.LittleEndian.Uint32(raw[8:12])), 10),
			line.ExtraInfo,
		)

		if raw[12] > 0 {
			require.Equal(t, "ALLOW", line.Apparmor)
		} else {
			require.Equal(t, "DENIED", line.Apparmor)
		}

		// The strings are null terminated, so none of them contains one.
		for _, s := range []string{line.Operation, line.Executable, line.Name} {
			require.NotContains(t, s, "\x00")
		}

		strs := bytes.Split(raw[bpfAuditHeaderSize:], []byte{0})
		require.Equal(t, string(strs[0]), line.Operation)
		require.Equal(t, string(strs[1]), line.Executable)
		require.Equal(t, string(strs[2]), line.Name)
	})
}
