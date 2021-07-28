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
	"testing"

	"github.com/stretchr/testify/require"
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
			//nolint:lll
			`audit: type=1326 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000`,
			true,
		},
		{
			"Should identify type=1326 lines with timestamp",
			//nolint:lll
			`Jul  8 10:31:23 ubuntu2004 kernel: [  270.853767] audit: type=1326 audit(1625740283.502:574): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=4709 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=13 compat=0 ip=0x7f3c012e467b code=0x7ffc0000`,
			true,
		},
		{
			"Should identify type=SECCOMP log lines",
			//nolint:lll
			`type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=system_u:system_r:spc_t:s0:c284,c594 pid=2039886 comm="ls" exe="/bin/ls" sig=0 arch=c000003e syscall=3 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000AUID="unset" UID="root" GID="root" ARCH=x86_64 SYSCALL=close`,
			true,
		},
		{
			"Should ignore unsupported log types",
			//nolint:lll
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
			//nolint:lll
			`type=AVC msg=audit(1613173578.156:2945): avc:  denied  { read } for  pid=75593 comm="security-profil" name="token" dev="tmpfs" ino=612459 scontext=system_u:system_r:container_t:s0:c4,c808 tcontext=system_u:object_r:var_lib_t:s0 tclass=lnk_file permissive=0`,
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isAuditLine(tt.logLine)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_extractAuditLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		logLine string
		want    *auditLine
		wantErr error
	}{
		{
			"Should extract seccomp log lines",
			//nolint:lll
			`audit: type=1326 audit(1612299677.115:549067): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=3109464 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7fce771ae923 code=0x7ffc0000`,
			&auditLine{
				type_:        "seccomp",
				timestampID:  "1612299677.115:549067",
				systemCallID: 0,
				processID:    3109464,
				executable:   "/bin/busybox",
			},
			nil,
		},
		{
			"Should extract seccomp log lines",
			//nolint:lll
			`type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 ses=4294967295 subj=system_u:system_r:spc_t:s0:c284,c594 pid=2039886 comm="ls" exe="/bin/ls" sig=0 arch=c000003e syscall=3 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000AUID="unset" UID="root" GID="root" ARCH=x86_64 SYSCALL=close`,
			&auditLine{
				type_:        "seccomp",
				timestampID:  "1613596317.899:6461",
				systemCallID: 3,
				processID:    2039886,
				executable:   "/bin/ls",
			},
			nil,
		},
		{
			"Should extract selinux log lines",
			//nolint:lll
			`type=AVC msg=audit(1613173578.156:2945): avc:  denied  { read } for  pid=75593 comm="security-profil" name="token" dev="tmpfs" ino=612459 scontext=system_u:system_r:container_t:s0:c4,c808 tcontext=system_u:object_r:var_lib_t:s0 tclass=lnk_file permissive=0`,
			&auditLine{
				type_:        "selinux",
				timestampID:  "1613173578.156:2945",
				systemCallID: 0,
				processID:    75593,
				executable:   "",
				perm:         "read",
				scontext:     "system_u:system_r:container_t:s0:c4,c808",
				tcontext:     "system_u:object_r:var_lib_t:s0",
				tclass:       "lnk_file",
			},
			nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, gotErr := extractAuditLine(tt.logLine)

			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantErr, gotErr)
		})
	}
}
