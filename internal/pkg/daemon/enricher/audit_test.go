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
			"Should identify seccomp log lines",
			//nolint:lll
			`audit: type=1326 audit(1611996299.149:466250): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=615549 comm="sh" exe="/bin/busybox" sig=0 arch=c000003e syscall=1 compat=0 ip=0x7f61a81c5923 code=0x7ffc0000`,
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
				Type:         "seccomp",
				TimestampID:  "1612299677.115:549067",
				SystemCallID: 0,
				ProcessID:    3109464,
				Executable:   "/bin/busybox",
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
