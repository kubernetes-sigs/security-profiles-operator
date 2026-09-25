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
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
)

const (
	processCacheTimeout = time.Minute
	// These have to match the C data structure in recorder.bpf.c.
	maxArgs        int = 20
	maxEnv         int = 50
	maxFileNameLen int = 128
	maxArgLen          = 64
	maxEnvLen          = 64
)

type bpfExecEvent struct {
	Pid      uint32
	Mntns    uint32
	Key      uint64
	Type     uint8
	Flags    uint64
	Filename [maxFileNameLen]uint8
	Args     [maxArgs][maxArgLen]uint8
	Env      [maxEnv][maxEnvLen]uint8
	ArgsLen  uint32
	EnvLen   uint32
}

// bpfExecEventSize is the packed wire size of bpfExecEvent.
const bpfExecEventSize = bpfEventHeaderSize +
	maxFileNameLen +
	maxArgs*maxArgLen +
	maxEnv*maxEnvLen +
	4 + 4

// unmarshal decodes a bpfExecEvent from the raw ring buffer bytes, avoiding the
// reflection cost of binary.Read over the embedded fixed-size arrays.
func (e *bpfExecEvent) unmarshal(raw []byte) bool {
	if len(raw) < bpfExecEventSize {
		return false
	}

	e.Pid, e.Mntns, e.Key, e.Type, e.Flags = unmarshalHeader(raw)

	off := bpfEventHeaderSize
	off += copy(e.Filename[:], raw[off:off+maxFileNameLen])

	for i := range maxArgs {
		off += copy(e.Args[i][:], raw[off:off+maxArgLen])
	}

	for i := range maxEnv {
		off += copy(e.Env[i][:], raw[off:off+maxEnvLen])
	}

	e.ArgsLen = binary.LittleEndian.Uint32(raw[off : off+4])
	off += 4
	e.EnvLen = binary.LittleEndian.Uint32(raw[off : off+4])

	return true
}

type BpfProcessInfo struct {
	Pid     int
	CmdLine string
	Env     map[string]string
}

type BpfProcessCache struct {
	recorder *BpfRecorder
	logger   logr.Logger
	cache    *ttlcache.Cache[int, *BpfProcessInfo]
}

func NewBpfProcessCache(logger logr.Logger) *BpfProcessCache {
	bpfProcCache := &BpfProcessCache{
		recorder: New("", logger, false, false),
		logger:   logger,
		cache: ttlcache.New(
			ttlcache.WithTTL[int, *BpfProcessInfo](processCacheTimeout),
			ttlcache.WithCapacity[int, *BpfProcessInfo](maxCacheItems),
		),
	}

	return bpfProcCache
}

func (b *BpfProcessCache) Load() (err error) {
	var module *bpf.Module

	b.logger.Info("Loading bpf module...")

	bpfObject, err := bpfObjectForArch(runtime.GOARCH)
	if err != nil {
		return err
	}

	module, err = b.recorder.NewModuleFromBufferArgs(&bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
		BTFObjPath: b.recorder.btfPath,
	})
	if err != nil {
		return fmt.Errorf("load bpf module: %w", err)
	}

	b.recorder.module = module

	// The recorder shares the BPF program, but only the process cache needs
	// the arguments and environment of each exec.
	if err := b.recorder.InitGlobalVariable(module, globalCaptureExecArgs, true); err != nil {
		return fmt.Errorf("init global variable: %w", err)
	}

	b.logger.Info("Loading bpf object from module")

	if err := b.recorder.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	if err := b.recorder.loadPrograms(procCacheHooks); err != nil {
		return fmt.Errorf("loading base hooks: %w", err)
	}

	b.recorder.isRecordingBpfMap, err = b.recorder.GetMap(b.recorder.module, mapIsRecording)
	if err != nil {
		return fmt.Errorf("getting `is_recording` map: %w", err)
	}

	const timeout = 300

	events := make(chan []byte)

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

	b.logger.Info("BPF module successfully loaded.")

	if err := b.recorder.StartRecording(); err != nil {
		return fmt.Errorf("StartRecording self-test: %w", err)
	}

	b.logger.Info("Started Recorder")

	go b.cache.Start()

	return nil
}

func (b *BpfProcessCache) GetCmdLine(pid int) (cmdLine string, err error) {
	item := b.cache.Get(pid)
	if item != nil {
		return item.Value().CmdLine, nil
	}

	return "", errors.New("no process info for Pid")
}

func (b *BpfProcessCache) GetEnv(pid int) (env map[string]string, err error) {
	item := b.cache.Get(pid)
	if item != nil {
		return item.Value().Env, nil
	}

	return nil, errors.New("no process info for Pid")
}

func (b *BpfProcessCache) processEvents(events chan []byte) {
	b.logger.Info("Processing bpf events")
	defer b.logger.Info("Stopped processing bpf events")

	for event := range events {
		b.handleEvent(event)
	}
}

func (b *BpfProcessCache) handleEvent(eventBytes []byte) {
	// The exec hook also reports the start of containers, which carries no
	// process information.
	if len(eventBytes) >= bpfEventHeaderSize && eventBytes[16] != eventTypeExecveEnter {
		return
	}

	var execEvent bpfExecEvent

	if !execEvent.unmarshal(eventBytes) {
		b.logger.Error(
			errShortEvent, "Couldn't read event structure",
			"got", len(eventBytes), "want", bpfExecEventSize,
		)

		return
	}

	b.logger.V(2).Info("eventTypeExecevEnter received", "execEvent", &execEvent)

	var cmdLineBuilder strings.Builder
	for i := range int(execEvent.ArgsLen) {
		cmdLineBuilder.WriteString(strings.ReplaceAll(string(execEvent.Args[i][:]), "\u0000", ""))
		cmdLineBuilder.WriteByte(' ')
	}

	cmdLine := cmdLineBuilder.String()

	envMap := make(map[string]string)

	for i := range int(execEvent.EnvLen) {
		envVar := string(execEvent.Env[i][:])

		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			key := strings.ReplaceAll(parts[0], "\u0000", "")
			key = strings.Trim(key, "\"")

			value := strings.ReplaceAll(parts[1], "\u0000", "")
			value = strings.Trim(value, "\"")

			envMap[key] = value
		}
	}

	pInfo := &BpfProcessInfo{
		Pid:     int(execEvent.Pid),
		CmdLine: cmdLine,
		Env:     envMap,
	}

	b.cache.Set(int(execEvent.Pid), pInfo, ttlcache.DefaultTTL)
	b.logger.V(2).Info("eventTypeExecevEnter processed", "pInfo", &pInfo)
}
