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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func Test_isAuditLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		logLine string
		want    bool
	}{
		{
			"Should identify type=1326 log lines",
			//nolint:lll // no need to wrap
			`audit: type=1326 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000`,
			true,
		},
		{
			"Should identify type=1326 lines with timestamp",
			//nolint:lll // no need to wrap
			`Jul  8 10:31:23 ubuntu2004 kernel: [  270.853767] audit: type=1326 audit(1625740283.502:574): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=4709 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=13 compat=0 ip=0x7f3c012e467b code=0x7ffc0000`,
			true,
		},
		{
			"Should identify type=SECCOMP log lines",
			//nolint:lll // no need to wrap
			`type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=system_u:system_r:spc_t:s0:c284,c594 pid=2039886 comm="ls" exe="/bin/ls" sig=0 arch=c000003e syscall=3 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000AUID="unset" UID="root" GID="root" ARCH=x86_64 SYSCALL=close`,
			true,
		},
		{
			"Should identify type=SECCOMP log lines from user activity inside the container",
			//nolint:lll // no need to wrap
			`type=SECCOMP msg=audit(1744780616.598:836036): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=system_u:system_r:container_t:s0:c83,c152 pid=72503 comm="sh" exe="/bin/dash" sig=0 arch=c000003e syscall=56 compat=0 ip=0x7fe2ff5017be code=0x7ffc0000AUID="unset" UID="root" GID="root" ARCH=x86_64 SYSCALL=clone`,
			true,
		},
		{
			"Should ignore unsupported log types",
			//nolint:lll // no need to wrap
			`audit: type=1016 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000`,
			false,
		},
		{
			"Should ignore unsupported log lines",
			`type=1326 syscall=1`,
			false,
		},
		{
			"Should identify SELinux log lines",
			//nolint:lll // no need to wrap
			`type=AVC msg=audit(1613173578.156:2945): avc:  denied  { read } for  pid=75593 comm="security-profil" name="token" dev="tmpfs" ino=612459 scontext=system_u:system_r:container_t:s0:c4,c808 tcontext=system_u:object_r:var_lib_t:s0 tclass=lnk_file permissive=0`,
			true,
		},
		{
			"Should extract selinux log lines with multiple permissions",
			//nolint:lll // no need to wrap
			`type=AVC msg=audit(1666691794.882:1434): avc:  denied  { read write open } for  pid=94509 comm="aide" path="/hostroot/etc/kubernetes/aide.log.new" dev="nvme0n1p4" ino=167774224 scontext=system_u:system_r:selinuxrecording.process:s0:c218,c875 tcontext=system_u:object_r:kubernetes_file_t:s0 tclass=file permissive=1`,
			true,
		},
		{
			"Should identify AppArmor log lines",
			//nolint:lll // no need to wrap
			`audit: type=1400 audit(1668191154.949:64): apparmor="DENIED" operation="exec" profile="profile-name" name="/usr/local/bin/sample-app" pid=4166 comm="tini"`,
			true,
		},
		{
			"Should identify AppArmor long log lines",
			//nolint:lll // no need to wrap
			`audit: type=1400 audit(1668191154.949:64): apparmor="DENIED" operation="exec" profile="profile-name" name="/usr/local/bin/sample-app" pid=4166 comm="tini" requested_mask="x" denied_mask="x" fsuid=65534 ouid=0`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := IsAuditLine(tt.logLine)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_extractAuditLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		logLine string
		want    *types.AuditLine
		wantErr error
	}{
		{
			"Should extract seccomp log lines",
			//nolint:lll // no need to wrap
			`audit: type=1326 audit(1612299677.115:549067): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`,
			&types.AuditLine{
				AuditType:    "seccomp",
				TimestampID:  "1612299677.115:549067",
				SystemCallID: 0,
				ProcessID:    3109464,
				Executable:   "/bin/busybox",
				Arch:         "c000003e",
			},
			nil,
		},
		{
			"Should extract seccomp log lines",
			//nolint:lll // no need to wrap
			`type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=system_u:system_r:spc_t:s0:c284,c594 pid=2039886 comm="ls" exe="/bin/ls" sig=0 arch=c000003e syscall=3 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000AUID="unset" UID="root" GID="root" ARCH=x86_64 SYSCALL=close`,
			&types.AuditLine{
				AuditType:    "seccomp",
				TimestampID:  "1613596317.899:6461",
				SystemCallID: 3,
				ProcessID:    2039886,
				Executable:   "/bin/ls",
				Arch:         "c000003e",
			},
			nil,
		},
		{
			"Should extract selinux log lines",
			//nolint:lll // no need to wrap
			`type=AVC msg=audit(1613173578.156:2945): avc:  denied  { read } for  pid=75593 comm="security-profil" name="token" dev="tmpfs" ino=612459 scontext=system_u:system_r:container_t:s0:c4,c808 tcontext=system_u:object_r:var_lib_t:s0 tclass=lnk_file permissive=0`,
			&types.AuditLine{
				AuditType:    "selinux",
				TimestampID:  "1613173578.156:2945",
				SystemCallID: 0,
				ProcessID:    75593,
				Executable:   "",
				Perm:         "read",
				Scontext:     "system_u:system_r:container_t:s0:c4,c808",
				Tcontext:     "system_u:object_r:var_lib_t:s0",
				Tclass:       "lnk_file",
			},
			nil,
		},
		{
			"Should extract selinux log lines with multiple permissions",
			//nolint:lll // no need to wrap
			`type=AVC msg=audit(1666691794.882:1434): avc:  denied  { read write open } for  pid=94509 comm="aide" path="/hostroot/etc/kubernetes/aide.log.new" dev="nvme0n1p4" ino=167774224 scontext=system_u:system_r:selinuxrecording.process:s0:c218,c875 tcontext=system_u:object_r:kubernetes_file_t:s0 tclass=file permissive=1`,
			&types.AuditLine{
				AuditType:    "selinux",
				TimestampID:  "1666691794.882:1434",
				SystemCallID: 0,
				ProcessID:    94509,
				Executable:   "",
				Perm:         "read write open",
				Scontext:     "system_u:system_r:selinuxrecording.process:s0:c218,c875",
				Tcontext:     "system_u:object_r:kubernetes_file_t:s0",
				Tclass:       "file",
			},
			nil,
		},
		{
			"Should extract apparmor log lines",
			//nolint:lll // no need to wrap
			`audit: type=1400 audit(1668191154.949:64): apparmor="DENIED" operation="exec" profile="profile-name" name="/usr/local/bin/sample-app" pid=4166 comm="tini"`,
			&types.AuditLine{
				AuditType:   "apparmor",
				TimestampID: "1668191154.949:64",
				ProcessID:   4166,
				Apparmor:    "DENIED",
				Operation:   "exec",
				Profile:     "profile-name",
				Name:        "/usr/local/bin/sample-app",
				Executable:  "tini",
			},
			nil,
		},
		{
			"Should extract apparmor long log lines",
			//nolint:lll // no need to wrap
			`audit: type=1400 audit(1668191154.949:64): apparmor="DENIED" operation="exec" profile="profile-name" name="/usr/local/bin/sample-app" pid=4166 comm="tini" requested_mask="x" denied_mask="x" fsuid=65534 ouid=0`,
			&types.AuditLine{
				AuditType:   "apparmor",
				TimestampID: "1668191154.949:64",
				ProcessID:   4166,
				Apparmor:    "DENIED",
				Operation:   "exec",
				Profile:     "profile-name",
				Name:        "/usr/local/bin/sample-app",
				Executable:  "tini",
				ExtraInfo:   "requested_mask='x' denied_mask='x' fsuid=65534 ouid=0",
			},
			nil,
		},
		{
			"Should extract seccomp log lines with a hex encoded executable",
			//nolint:lll // no need to wrap
			`type=SECCOMP msg=audit(1613596317.899:6462): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=2039887 comm=6D7920617070 exe=2F6F70742F6D79206170702F62696E sig=0 arch=c000003e syscall=2 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000`,
			&types.AuditLine{
				AuditType:    "seccomp",
				TimestampID:  "1613596317.899:6462",
				SystemCallID: 2,
				ProcessID:    2039887,
				Executable:   "/opt/my app/bin",
				Arch:         "c000003e",
			},
			nil,
		},
		{
			"Should extract seccomp log lines of a compat syscall",
			//nolint:lll // no need to wrap
			`type=SECCOMP msg=audit(1613596317.899:6463): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=2039888 comm="app32" exe="/app32" sig=0 arch=40000003 syscall=102 compat=1 ip=0xf7f2a549 code=0x7ffc0000`,
			&types.AuditLine{
				AuditType:    "seccomp",
				TimestampID:  "1613596317.899:6463",
				SystemCallID: 102,
				ProcessID:    2039888,
				Executable:   "/app32",
				Arch:         "40000003",
			},
			nil,
		},
		{
			"Should ignore the fields auditd appends",
			"type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 " +
				"pid=2039886 comm=\"ls\" exe=\"/bin/ls\" sig=0 arch=c000003e syscall=3 compat=0 " +
				"ip=0x7f62dce3d4c7 code=0x7ffc0000\x1dAUID=\"unset\" UID=\"root\" ARCH=x86_64 SYSCALL=close pid=1",
			&types.AuditLine{
				AuditType:    "seccomp",
				TimestampID:  "1613596317.899:6461",
				SystemCallID: 3,
				ProcessID:    2039886,
				Executable:   "/bin/ls",
				Arch:         "c000003e",
			},
			nil,
		},
		{
			"Should extract apparmor log lines with a hex encoded comm",
			//nolint:lll // no need to wrap
			`audit: type=1400 audit(1668191154.949:65): apparmor="DENIED" operation="open" profile="profile-name" name="/etc/shadow" pid=4167 comm=4332204361636865 requested_mask="r" denied_mask="r" fsuid=0 ouid=0`,
			&types.AuditLine{
				AuditType:   "apparmor",
				TimestampID: "1668191154.949:65",
				ProcessID:   4167,
				Apparmor:    "DENIED",
				Operation:   "open",
				Profile:     "profile-name",
				Name:        "/etc/shadow",
				Executable:  "C2 Cache",
				ExtraInfo:   "requested_mask='r' denied_mask='r' fsuid=0 ouid=0",
			},
			nil,
		},
		{
			"Should extract apparmor capability log lines",
			//nolint:lll // no need to wrap
			`type=AVC msg=audit(1668191154.949:66): apparmor="DENIED" operation="capable" class="cap" profile="profile-name" pid=4168 comm="ping" capability=13  capname="net_raw"`,
			&types.AuditLine{
				AuditType:   "apparmor",
				TimestampID: "1668191154.949:66",
				ProcessID:   4168,
				Apparmor:    "DENIED",
				Operation:   "capable",
				Profile:     "profile-name",
				Executable:  "ping",
				ExtraInfo:   "capability=13 capname='net_raw'",
			},
			nil,
		},
		{
			"Should extract apparmor network log lines",
			//nolint:lll // no need to wrap
			`audit: type=1400 audit(1668191154.949:67): apparmor="DENIED" operation="create" class="net" profile="profile-name" pid=4169 comm="curl" family="inet" sock_type="raw" protocol=1 requested_mask="create" denied_mask="create"`,
			&types.AuditLine{
				AuditType:   "apparmor",
				TimestampID: "1668191154.949:67",
				ProcessID:   4169,
				Apparmor:    "DENIED",
				Operation:   "create",
				Profile:     "profile-name",
				Executable:  "curl",
				ExtraInfo: "family='inet' sock_type='raw' protocol=1 " +
					"requested_mask='create' denied_mask='create'",
			},
			nil,
		},
		{
			"Should extract selinux lines of the kernel log",
			//nolint:lll // no need to wrap
			`[  12.345678] audit: type=1400 audit(1613173578.156:2946): avc:  denied  { write } for  pid=75594 comm="app" name="data" dev="tmpfs" ino=612460 scontext=system_u:system_r:container_t:s0:c4,c808 tcontext=system_u:object_r:var_lib_t:s0 tclass=dir permissive=0`,
			&types.AuditLine{
				AuditType:   "selinux",
				TimestampID: "1613173578.156:2946",
				ProcessID:   75594,
				Perm:        "write",
				Scontext:    "system_u:system_r:container_t:s0:c4,c808",
				Tcontext:    "system_u:object_r:var_lib_t:s0",
				Tclass:      "dir",
			},
			nil,
		},
		{
			"Should extract seccomp lines of s390",
			`type=SECCOMP msg=audit(1613596317.899:6464): pid=7 comm="a" exe="/a" arch=16 syscall=102 compat=0`,
			&types.AuditLine{
				AuditType:    "seccomp",
				TimestampID:  "1613596317.899:6464",
				SystemCallID: 102,
				ProcessID:    7,
				Executable:   "/a",
				Arch:         "16",
			},
			nil,
		},
		{
			"Should not extract seccomp lines without a syscall",
			`type=SECCOMP msg=audit(1613596317.899:6461): pid=2039886 comm="ls" exe="/bin/ls"`,
			nil,
			fmt.Errorf(
				"unsupported log line: %s",
				`type=SECCOMP msg=audit(1613596317.899:6461): pid=2039886 comm="ls" exe="/bin/ls"`,
			),
		},
		{
			"Should not extract suppressed lines",
			`[ 3683.829070] kauditd_printk_skb: 1 callbacks suppressed`,
			nil,
			fmt.Errorf(
				"unsupported log line: %s",
				`[ 3683.829070] kauditd_printk_skb: 1 callbacks suppressed`,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, gotErr := ExtractAuditLine(tt.logLine)

			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantErr, gotErr)
		})
	}
}

func TestGetUidGid(t *testing.T) {
	t.Parallel()

	uid, gid, err := GetUidGid(
		"auid=4294967295 uid=0 gid=0 ses=4294967295 " +
			"subj=system_u:system_r:container_t:s0:c692,c728")
	require.NoError(t, err)
	require.Equal(t, uint32(0), uid)
	require.Equal(t, uint32(0), gid)
}

func TestExtractAuditLineUidGid(t *testing.T) {
	t.Parallel()

	//nolint:lll // no need to wrap
	auditLineTest := `audit: type=1326 audit(1612299677.115:549067): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`
	_, err := ExtractAuditLine(auditLineTest)
	require.NoError(t, err)

	uid, gid, errUidGid := GetUidGid(auditLineTest)
	require.NoError(t, errUidGid)
	require.Equal(t, uint32(0), uid)
	require.Equal(t, uint32(0), gid)
}

func TestExtractAuditLineUidGidInvalidAuditLine(t *testing.T) {
	t.Parallel()

	//nolint:lll // no need to wrap
	auditLineTest := `audit: type=1326 audit(1612299677.115:549067): auid=4294967295 ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`
	_, _, err := GetUidGid(auditLineTest)
	require.Error(t, err)
}

func TestExtractAuditLineUidGidInvalid(t *testing.T) {
	t.Parallel()

	//nolint:lll // no need to wrap
	auditLineTest := `audit: type=1326 audit(1612299677.115:549067): auid=4294967295 uid=invalid gid=0 ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`
	_, _, errUid := GetUidGid(auditLineTest)
	require.Error(t, errUid)

	//nolint:lll // no need to wrap
	auditLineTest = `audit: type=1326 audit(1612299677.115:549067): auid=4294967295 uid=0 gid=invalid ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`
	_, _, errGid := GetUidGid(auditLineTest)
	require.Error(t, errGid)
}
