//go:build linux && !no_bpf

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

package bpfrecorder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/libbpflog"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// processCacheTimeout is how long the arguments of an exec are kept. The
	// audit log is read with a delay, so a short lived process is often gone
	// before its lines are processed.
	processCacheTimeout = 2 * time.Minute
	// maxProcessCacheItems bounds the execs kept. It covers the execs of the
	// host and the containers within the timeout, as the JSON enricher emits
	// the lines of both.
	maxProcessCacheItems uint64 = 8 * 1024
	// These have to match the C data structure in recorder.bpf.c.
	maxExecArgsLen = 4096
	maxExecEnvLen  = 8192
	// bpfExecEventDataOffset is where the arguments start, after the header,
	// the lengths of the arguments and the environment, and the gap of the
	// latter.
	bpfExecEventDataOffset = bpfEventHeaderSize + 4 + 4 + 4
)

type bpfExecEvent struct {
	Pid   uint32
	Mntns uint32
	Key   uint64
	Type  uint8
	Flags uint64
	// Args and Env are NUL separated strings, like /proc/<pid>/cmdline.
	Args []byte
	Env  []byte
	// EnvGap is the offset in Env where the middle of a long environment got
	// left out, 0 if it is complete.
	EnvGap int
}

// unmarshal decodes a bpfExecEvent from the raw ring buffer bytes. The BPF
// program only sends as much of the event as the arguments and the
// environment need, Args and Env point into raw.
func (e *bpfExecEvent) unmarshal(raw []byte) bool {
	if len(raw) < bpfExecEventDataOffset {
		return false
	}

	e.Pid, e.Mntns, e.Key, e.Type, e.Flags = unmarshalHeader(raw)

	argsLen := int(binary.LittleEndian.Uint32(raw[bpfEventHeaderSize:]))
	envLen := int(binary.LittleEndian.Uint32(raw[bpfEventHeaderSize+4:]))
	e.EnvGap = int(binary.LittleEndian.Uint32(raw[bpfEventHeaderSize+8:]))

	if argsLen > maxExecArgsLen || envLen > maxExecEnvLen || e.EnvGap > envLen ||
		len(raw) < bpfExecEventDataOffset+argsLen+envLen {
		return false
	}

	data := raw[bpfExecEventDataOffset:]
	e.Args = data[:argsLen]
	e.Env = data[argsLen : argsLen+envLen]

	return true
}

// execArgs returns the NUL separated arguments of buf. A last argument without
// terminator got truncated by the BPF program, it still tells what got
// executed.
func execArgs(buf []byte) []string {
	if len(buf) == 0 {
		return nil
	}

	return strings.Split(string(bytes.TrimSuffix(buf, []byte{0})), "\x00")
}

// execRequestUID returns the non-empty request UID in the NUL separated
// environment env, like enricher.ExecRequestIDForPID does for the process file
// system. A variable the BPF program cut is left out, its value would be
// wrong. Of a long environment, the BPF program sends the byte before its end
// at gap, so the first variable after gap is complete if that is a NUL.
func execRequestUID(env []byte, gap int) string {
	parts := [][]byte{env}

	if gap > 0 {
		_, tail, _ := bytes.Cut(env[gap:], []byte{0})
		parts = [][]byte{env[:gap], tail}
	}

	prefix := []byte(config.ExecRequestUIDEnvKey + "=")

	for _, part := range parts {
		for {
			entry, rest, terminated := bytes.Cut(part, []byte{0})
			if !terminated {
				break
			}

			if value, ok := bytes.CutPrefix(entry, prefix); ok && len(value) > 0 {
				return string(value)
			}

			part = rest
		}
	}

	return ""
}

type BpfProcessInfo struct {
	Pid  int
	Args []string
	// RequestUID is the request UID of the environment, see
	// config.ExecRequestUIDEnvKey. The rest of the environment is not kept,
	// it can carry credentials.
	RequestUID string
	// StartedAt is when the process started, since boot. It is zero if the
	// BPF program could not tell.
	StartedAt time.Duration
}

type BpfProcessCache struct {
	recorder *BpfRecorder
	logger   logr.Logger
	cache    *ttlcache.Cache[int, *BpfProcessInfo]
	// startTime returns when the process with the PID started, a field so
	// that tests can fake the processes.
	startTime func(int) (time.Duration, error)
}

// errProcessReplaced is returned for a PID whose cached exec belongs to a
// process which is gone, while another one runs with the PID now.
var errProcessReplaced = errors.New("another process runs with the PID since its exec")

func NewBpfProcessCache(logger logr.Logger) *BpfProcessCache {
	recorder := New("", logger, false, false)
	recorder.lostRingbufImpact = "enriched audit records may miss the command line " +
		"and the request UID of their process"

	bpfProcCache := &BpfProcessCache{
		recorder: recorder,
		logger:   logger,
		cache: ttlcache.New(
			ttlcache.WithTTL[int, *BpfProcessInfo](processCacheTimeout),
			ttlcache.WithCapacity[int, *BpfProcessInfo](maxProcessCacheItems),
			// The arguments of an exec do not change, so a lookup must not
			// keep them beyond the timeout.
			ttlcache.WithDisableTouchOnHit[int, *BpfProcessInfo](),
		),
		startTime: util.ProcessStartTime,
	}

	return bpfProcCache
}

func (b *BpfProcessCache) Load() (err error) {
	var module *bpf.Module

	libbpflog.Route(b.logger)
	b.logger.Info("Loading bpf module...")

	bpfObject, err := bpfObjectForArch(runtime.GOARCH)
	if err != nil {
		return err
	}

	module, err = b.recorder.NewModuleFromBufferArgs(&bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
	})
	if err != nil {
		return fmt.Errorf("load bpf module: %w", err)
	}

	b.recorder.module = module

	// Unload the module again if anything below fails, it would keep its
	// programs and maps otherwise.
	defer func() {
		if err != nil {
			b.recorder.Close()
		}
	}()

	// Only the exec hooks are needed, everything else would just cost
	// verification time, and the LSM hooks fail loading the whole object on
	// kernels without the BPF LSM.
	if err := b.recorder.disableProgramsExcept(module, procCacheHooks); err != nil {
		return err
	}

	// The maps of the recorder would take megabytes of kernel memory for
	// nothing. The ones the hooks refer to have to be created, even if they
	// stay empty.
	if err := b.recorder.skipMaps(module, procCacheSkippedMaps); err != nil {
		return err
	}

	if err := b.recorder.shrinkMaps(module, procCacheUnusedMaps); err != nil {
		return err
	}

	b.logger.Info("Loading bpf object from module")

	if err := b.recorder.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	if _, err := b.recorder.attachPrograms(procCacheHooks); err != nil {
		return fmt.Errorf("loading base hooks: %w", err)
	}

	b.recorder.isRecordingBpfMap, err = b.recorder.GetMap(b.recorder.module, mapIsRecording)
	if err != nil {
		return fmt.Errorf("getting `is_recording` map: %w", err)
	}

	// A full ring buffer drops exec events, which leaves the enriched
	// records without the command line.
	lostEvents, err := b.recorder.GetMap(b.recorder.module, mapLostEvents)
	if err != nil {
		return fmt.Errorf("getting `%s` map: %w", mapLostEvents, err)
	}

	b.recorder.lostEventsMu.Lock()
	b.recorder.lostEventsBpfMap = lostEvents
	b.recorder.lostEventsMu.Unlock()

	const timeout = 300

	events := make(chan []byte, eventsQueueSize)

	ringbuf, err := b.recorder.InitRingBuf(
		b.recorder.module,
		mapEvents,
		events,
	)
	if err != nil {
		return fmt.Errorf("init events ringbuffer: %w", err)
	}

	b.recorder.PollRingBuffer(ringbuf, timeout)

	go b.processEvents(events)
	go b.recorder.reportLostEvents()

	b.logger.Info("BPF module successfully loaded.")

	if err := b.recorder.StartRecording(); err != nil {
		return fmt.Errorf("StartRecording self-test: %w", err)
	}

	b.logger.Info("Started Recorder")

	go b.cache.Start()

	return nil
}

// Close unloads the BPF module and stops the cache.
func (b *BpfProcessCache) Close() {
	b.recorder.Close()
	b.cache.Stop()
}

// GetCmdLineAndRequestUID returns the command line, the arguments and the
// request UID of the environment of the last exec of the process with the PID.
// They come from a single lookup, which reads the start time of the process
// once. The exec of a process which exited is still returned, as the audit
// lines are read with a delay, unless another process runs with the PID by
// now: a process which only forked does not exec, it must not get the
// arguments and the request of the previous process with its PID. The command
// line has every argument followed by a space, the request UID is empty if the
// environment has none.
func (b *BpfProcessCache) GetCmdLineAndRequestUID(
	pid int,
) (cmdLine string, args []string, requestUID string, err error) {
	item := b.cache.Get(pid)
	if item == nil {
		return "", nil, "", errors.New("no process info for Pid")
	}

	info := item.Value()
	if info.StartedAt > 0 {
		started, err := b.startTime(pid)
		if err == nil && started != info.StartedAt.Truncate(util.ProcessStartTimeTick) {
			return "", nil, "", fmt.Errorf("%w: pid %d", errProcessReplaced, pid)
		}
	}

	var cmdLineBuilder strings.Builder

	for _, arg := range info.Args {
		cmdLineBuilder.WriteString(arg)
		cmdLineBuilder.WriteByte(' ')
	}

	return cmdLineBuilder.String(), info.Args, info.RequestUID, nil
}

func (b *BpfProcessCache) processEvents(events chan []byte) {
	b.logger.Info("Processing bpf events")
	defer b.logger.Info("Stopped processing bpf events")

	for event := range events {
		b.handleEvent(event)
	}
}

func (b *BpfProcessCache) handleEvent(eventBytes []byte) {
	// The hooks of the process cache only report execs. Other events of the
	// object must not be read as exec events.
	if len(eventBytes) >= bpfEventHeaderSize && eventBytes[16] != eventTypeExec {
		return
	}

	var execEvent bpfExecEvent

	if !execEvent.unmarshal(eventBytes) {
		b.logger.Error(
			errShortEvent, "Couldn't read event structure",
			"got", len(eventBytes),
		)

		return
	}

	pInfo := &BpfProcessInfo{
		Pid:        int(execEvent.Pid),
		Args:       execArgs(execEvent.Args),
		RequestUID: execRequestUID(execEvent.Env, execEvent.EnvGap),
		// The flags carry when the process started, see submit_exec_event. A
		// value beyond a duration turns negative, which counts as unknown.
		//nolint:gosec // the overflow is intended, see above
		StartedAt: time.Duration(execEvent.Flags),
	}

	b.cache.Set(int(execEvent.Pid), pInfo, ttlcache.DefaultTTL)

	// The arguments are not logged, they are those of every exec on the node
	// and can carry credentials.
	b.logger.V(2).Info("Exec processed", "pid", execEvent.Pid)
}
