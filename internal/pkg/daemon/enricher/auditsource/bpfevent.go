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
// enricher.bpf.c: the mount namespace, the PID, the request, the complain
// flag and the time of the denial in nanoseconds since boot. The operation,
// the command, the name and the profile follow as strings which are each
// terminated by a null byte.
const bpfAuditHeaderSize = 4 + 4 + 4 + 1 + 8

var errInvalidBpfAuditEvent = errors.New("invalid audit event")

// parseBpfAuditEvent decodes an event of enricher.bpf.c which was received at
// now, which is sinceBoot after the boot. It returns the audit line and the
// mount namespace of the process.
func parseBpfAuditEvent(
	raw []byte, now time.Time, sinceBoot time.Duration,
) (*types.AuditLine, uint32, error) {
	if len(raw) <= bpfAuditHeaderSize {
		return nil, 0, fmt.Errorf("%w: %d bytes", errInvalidBpfAuditEvent, len(raw))
	}

	mntns := binary.LittleEndian.Uint32(raw[0:4])
	pid := int(binary.LittleEndian.Uint32(raw[4:8]))
	request := binary.LittleEndian.Uint32(raw[8:12])
	complain := raw[12]
	//nolint:gosec // The time since boot fits into a time.Duration.
	happened := time.Duration(binary.LittleEndian.Uint64(raw[13:21]))

	// Every string is terminated, so the last part is empty.
	strs := bytes.Split(raw[bpfAuditHeaderSize:], []byte{0})
	if len(strs) < 5 {
		return nil, 0, fmt.Errorf("%w: %d strings", errInvalidBpfAuditEvent, len(strs))
	}

	// The kernel reports the same values in the audit log.
	apparmor := "DENIED"
	if complain > 0 {
		apparmor = "ALLOWED"
	}

	// The line is timestamped with when the denial happened, which tells
	// whether the process with the PID now is the one of the line. Events can
	// queue up for a while in a burst.
	logged := now
	if happened > 0 && happened <= sinceBoot {
		logged = now.Add(happened - sinceBoot)
	}

	ts := logged.UnixMilli()

	return &types.AuditLine{
		AuditType:   types.AuditTypeApparmor,
		ProcessID:   pid,
		TimestampID: fmt.Sprintf("%d.%03d", ts/1000, ts%1000),
		Apparmor:    apparmor,
		Operation:   validUTF8(string(strs[0])),
		Executable:  validUTF8(string(strs[1])),
		Name:        validUTF8(string(strs[2])),
		Profile:     validUTF8(string(strs[3])),
		ExtraInfo:   fmt.Sprintf("request:%d", request),
	}, mntns, nil
}
