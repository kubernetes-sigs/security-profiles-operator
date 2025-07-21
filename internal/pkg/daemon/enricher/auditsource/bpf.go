//go:build linux && !no_bpf && (amd64 || arm64)

package auditsource

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

type BpfSource struct {
	logger logr.Logger
}

func NewBpfSource(logger logr.Logger) (*BpfSource, error) {
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
			mntns := binary.LittleEndian.Uint32(val[0:4])
			pid := int(binary.LittleEndian.Uint32(val[4:8]))
			request := binary.LittleEndian.Uint32(val[8:12])
			complain := val[12]
			strs := bytes.Split(val[13:], []byte("\x00"))
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
