//go:build linux && !no_bpf && (amd64 || arm64)

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

package auditsource

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/blang/semver/v4"
	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func BpfSupported(logger logr.Logger) error {
	_, version, err := util.Uname()
	if err != nil {
		logger.Error(err, "failed to get kernel version to check BPF support, continuing anyway...")

		return nil
	}

	minVersion := semver.Version{Major: 5, Minor: 19}

	if version.LT(minVersion) {
		return fmt.Errorf("unsupported kernel version: need %s but got %s", minVersion, version)
	}

	return nil
}

type BpfSource struct {
	logger logr.Logger
}

func NewBpfSource(logger logr.Logger) (*BpfSource, error) {
	if err := BpfSupported(logger); err != nil {
		return nil, err
	}

	return &BpfSource{
		logger: logger,
	}, nil
}

func (b *BpfSource) StartTail() (chan *types.AuditLine, error) {
	b.logger.Info("Loading bpf module...")

	module, err := libbpfgo.NewModuleFromBufferArgs(libbpfgo.NewModuleArgs{
		BPFObjBuff: AuditProgram,
		BPFObjName: "enricher.bpf.o",
	})
	if err != nil {
		return nil, fmt.Errorf("load bpf module: %w", err)
	}

	if err := module.BPFLoadObject(); err != nil {
		return nil, fmt.Errorf("load bpf object: %w", err)
	}

	if err := module.AttachPrograms(); err != nil {
		return nil, fmt.Errorf("load bpf object: %w", err)
	}

	events := make(chan []byte)

	buf, err := module.InitRingBuf("audit_log", events)
	if err != nil {
		return nil, fmt.Errorf("init ringbuf: %w", err)
	}

	buf.Poll(300)

	log := make(chan *types.AuditLine)

	go func() {
		for val := range events {
			if len(val) < 14 {
				b.logger.Info("received invalid audit log message", "val", val)

				break
			}

			mntns := binary.LittleEndian.Uint32(val[0:4])
			pid := int(binary.LittleEndian.Uint32(val[4:8]))
			request := binary.LittleEndian.Uint32(val[8:12])
			complain := val[12]
			strs := bytes.Split(val[13:], []byte("\x00"))

			if len(strs) < 3 {
				b.logger.Info("received invalid audit log message", "val", val)

				break
			}

			op := string(strs[0])
			comm := string(strs[1])
			name := string(strs[2])

			var apparmor string
			if complain > 0 {
				apparmor = "ALLOW"
			} else {
				apparmor = "DENIED"
			}

			ts := time.Now().UnixMilli()
			timestamp := fmt.Sprintf("%d.%03d", ts/1000, ts%1000)

			line := types.AuditLine{
				AuditType:   types.AuditTypeApparmor,
				ProcessID:   pid,
				TimestampID: timestamp,
				Apparmor:    apparmor,
				Operation:   op,
				Name:        name,
				Executable:  comm,
				ExtraInfo:   fmt.Sprintf("request:%d", request),
			}
			b.logger.Info("audit log event received", "mntns", mntns, "line", line)

			log <- &line
		}

		close(log)
	}()

	b.logger.Info("BPF module successfully loaded.")

	return log, nil
}

func (b *BpfSource) TailErr() error {
	return nil
}
