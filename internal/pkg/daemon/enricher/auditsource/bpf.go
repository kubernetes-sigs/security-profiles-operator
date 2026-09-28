//go:build linux && !no_bpf && (amd64 || arm64)

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
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/blang/semver/v4"
	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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

const (
	// auditLogRingBuf is the ring buffer of enricher.bpf.c.
	auditLogRingBuf = "audit_log"
	// lostEventsMap counts the events which did not fit into the ring buffer.
	lostEventsMap = "lost_events"

	// lostEventsInterval is how often the lost events are checked.
	lostEventsInterval = 30 * time.Second
)

type BpfSource struct {
	logger logr.Logger
	module *libbpfgo.Module
	buf    *libbpfgo.RingBuffer
	// done is closed by Stop, so that the goroutines of the source do not
	// wait for a consumer which is gone.
	done     chan struct{}
	stopOnce sync.Once
}

func NewBpfSource(logger logr.Logger) (*BpfSource, error) {
	if err := BpfSupported(logger); err != nil {
		return nil, err
	}

	return &BpfSource{
		logger: logger,
		done:   make(chan struct{}),
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

	// Every failure below has to release the module, otherwise the loaded
	// programs and maps stay pinned for the lifetime of the process.
	if err := module.BPFLoadObject(); err != nil {
		module.Close()

		return nil, fmt.Errorf("load bpf object: %w", err)
	}

	if err := module.AttachPrograms(); err != nil {
		module.Close()

		return nil, fmt.Errorf("attach bpf programs: %w", err)
	}

	events := make(chan []byte)

	buf, err := module.InitRingBuf(auditLogRingBuf, events)
	if err != nil {
		module.Close()

		return nil, fmt.Errorf("init ringbuf: %w", err)
	}

	b.module = module
	b.buf = buf

	buf.Poll(300)

	log := make(chan *types.AuditLine)

	go b.forward(events, log)

	if lost, err := module.GetMap(lostEventsMap); err != nil {
		b.logger.Error(err, "Unable to watch for lost audit events")
	} else {
		go b.reportLostEvents(lost)
	}

	b.logger.Info("BPF module successfully loaded.")

	return log, nil
}

// forward sends the events as audit lines to log until the events end or the
// source is stopped.
func (b *BpfSource) forward(events <-chan []byte, log chan<- *types.AuditLine) {
	defer close(log)

	for {
		var (
			val []byte
			ok  bool
		)

		select {
		case val, ok = <-events:
			if !ok {
				return
			}
		case <-b.done:
			return
		}

		line, mntns, err := parseBpfAuditEvent(val, time.Now())
		if err != nil {
			b.logger.Info("received invalid audit log message", "val", val, "error", err.Error())

			continue
		}

		b.logger.V(config.VerboseLevel).
			Info("audit log event received", "mntns", mntns, "line", line)

		select {
		case log <- line:
		case <-b.done:
			return
		}
	}
}

// reportLostEvents periodically logs the events which did not fit into the
// ring buffer. They are missing from the recorded profiles.
func (b *BpfSource) reportLostEvents(lostEvents *libbpfgo.BPFMap) {
	ticker := time.NewTicker(lostEventsInterval)
	defer ticker.Stop()

	var reported uint64

	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
		}

		key := uint32(0)

		value, err := lostEvents.GetValue(unsafe.Pointer(&key))
		if err != nil {
			b.logger.Error(err, "Unable to read lost audit events")

			continue
		}

		var total uint64
		for i := 0; i+8 <= len(value); i += 8 {
			total += binary.LittleEndian.Uint64(value[i : i+8])
		}

		if total > reported {
			b.logger.Info(
				"WARNING: the BPF ring buffer was full, audit events were lost",
				"lostEvents", total-reported, "lostEventsTotal", total,
			)
		}

		reported = total
	}
}

func (b *BpfSource) Stop() {
	b.stopOnce.Do(func() {
		close(b.done)
	})

	if b.buf != nil {
		b.buf.Stop()
		b.buf = nil
	}

	if b.module != nil {
		b.module.Close()
		b.module = nil
	}
}

func (b *BpfSource) TailErr() error {
	return nil
}
