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
	"errors"
	"fmt"
	"time"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// bpfAuditHeaderSize is the size of the fixed fields of an event of
// enricher.bpf.c: the mount namespace, the PID, the request and the complain
// flag. The operation, the command and the name follow as strings which are
// each terminated by a null byte.
const bpfAuditHeaderSize = 4 + 4 + 4 + 1

var errInvalidBpfAuditEvent = errors.New("invalid audit event")

// parseBpfAuditEvent decodes an event of enricher.bpf.c which was received at
// now. It returns the audit line and the mount namespace of the process.
func parseBpfAuditEvent(raw []byte, now time.Time) (*types.AuditLine, uint32, error) {
	if len(raw) <= bpfAuditHeaderSize {
		return nil, 0, fmt.Errorf("%w: %d bytes", errInvalidBpfAuditEvent, len(raw))
	}

	mntns := binary.LittleEndian.Uint32(raw[0:4])
	pid := int(binary.LittleEndian.Uint32(raw[4:8]))
	request := binary.LittleEndian.Uint32(raw[8:12])
	complain := raw[12]

	strs := bytes.Split(raw[bpfAuditHeaderSize:], []byte{0})
	if len(strs) < 3 {
		return nil, 0, fmt.Errorf("%w: %d strings", errInvalidBpfAuditEvent, len(strs))
	}

	apparmor := "DENIED"
	if complain > 0 {
		apparmor = "ALLOW"
	}

	ts := now.UnixMilli()

	return &types.AuditLine{
		AuditType:   types.AuditTypeApparmor,
		ProcessID:   pid,
		TimestampID: fmt.Sprintf("%d.%03d", ts/1000, ts%1000),
		Apparmor:    apparmor,
		Operation:   validUTF8(string(strs[0])),
		Executable:  validUTF8(string(strs[1])),
		Name:        validUTF8(string(strs[2])),
		ExtraInfo:   fmt.Sprintf("request:%d", request),
	}, mntns, nil
}
