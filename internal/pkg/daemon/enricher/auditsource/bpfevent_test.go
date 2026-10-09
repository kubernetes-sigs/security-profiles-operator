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
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func bpfAuditEvent(mntns, request uint32, complain byte, strs ...string) []byte {
	raw := binary.LittleEndian.AppendUint32(nil, mntns)
	raw = binary.LittleEndian.AppendUint32(raw, testPid)
	raw = binary.LittleEndian.AppendUint32(raw, request)
	raw = append(raw, complain)

	for _, s := range strs {
		raw = append(raw, s...)
		raw = append(raw, 0)
	}

	return raw
}

const testPid = 42

func TestParseBpfAuditEvent(t *testing.T) {
	t.Parallel()

	now := time.UnixMilli(1700000000042)

	t.Run("denied", func(t *testing.T) {
		t.Parallel()

		line, mntns, err := parseBpfAuditEvent(
			bpfAuditEvent(4026531840, 4, 0, "open", "cat", "/etc/shadow"), now,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(4026531840), mntns)
		require.Equal(t, &types.AuditLine{
			AuditType:   types.AuditTypeApparmor,
			ProcessID:   testPid,
			TimestampID: "1700000000.042",
			Apparmor:    "DENIED",
			Operation:   "open",
			Executable:  "cat",
			Name:        "/etc/shadow",
			ExtraInfo:   "request:4",
		}, line)
	})

	t.Run("complain mode allows", func(t *testing.T) {
		t.Parallel()

		line, _, err := parseBpfAuditEvent(bpfAuditEvent(1, 2, 1, "exec", "sh", "/bin/ls"), now)
		require.NoError(t, err)
		require.Equal(t, "ALLOW", line.Apparmor)
	})

	t.Run("empty strings", func(t *testing.T) {
		t.Parallel()

		line, _, err := parseBpfAuditEvent(bpfAuditEvent(1, 0, 0, "", "", ""), now)
		require.NoError(t, err)
		require.Empty(t, line.Operation)
		require.Empty(t, line.Executable)
		require.Empty(t, line.Name)
	})

	// The strings end up in protobuf messages, which take valid UTF-8 only.
	t.Run("invalid UTF-8", func(t *testing.T) {
		t.Parallel()

		line, _, err := parseBpfAuditEvent(
			bpfAuditEvent(1, 0, 0, "open\xff", "c\xfeat", "/etc/\xc0\xaf"), now,
		)
		require.NoError(t, err)
		require.Equal(t, "open\uFFFD", line.Operation)
		require.Equal(t, "c\uFFFDat", line.Executable)
		require.Equal(t, "/etc/\uFFFD", line.Name)
	})

	for name, raw := range map[string][]byte{
		"empty":           nil,
		"header only":     bpfAuditEvent(1, 0, 0),
		"missing strings": bpfAuditEvent(1, 0, 0, "open"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := parseBpfAuditEvent(raw, now)
			require.ErrorIs(t, err, errInvalidBpfAuditEvent)
		})
	}
}
