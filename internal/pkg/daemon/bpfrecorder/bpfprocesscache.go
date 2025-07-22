//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2021 The Kubernetes Authors.

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
)

const (
	processCacheTimeout = time.Minute
	// These have to match the C data structure in recorder.bpf.c
	maxArgs        int = 20
	maxEnv         int = 50
	maxFileNameLen int = 128
	maxArgLen          = 64
	maxEnvLen          = 64
)

type bpfExecEvent struct {
	bpfEvent
	Filename [maxFileNameLen]uint8
	Args     [maxArgs][maxArgLen]uint8
	Env      [maxEnv][maxEnvLen]uint8
	ArgsLen  uint32
	EnvLen   uint32
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

	var bpfObject []byte

	switch b.recorder.GoArch() {
	case "amd64":
		bpfObject = bpfAmd64
	case "arm64":
		bpfObject = bpfArm64
	default:
		return fmt.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
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

	b.logger.Info("Loading bpf object from module")

	if err := b.recorder.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	procCacheHooks := []string{
		"sys_enter_execve",
		"sys_enter_getgid",
	}

	if err := b.recorder.loadPrograms(procCacheHooks); err != nil {
		return fmt.Errorf("loading base hooks: %w", err)
	}

	b.recorder.isRecordingBpfMap, err = b.recorder.GetMap(b.recorder.module, "is_recording")
	if err != nil {
		return fmt.Errorf("getting `is_recording` map: %w", err)
	}

	const timeout = 300

	events := make(chan []byte)

	ringbuf, err := b.recorder.InitRingBuf(
		b.recorder.module,
		"events",
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
	var execEvent bpfExecEvent

	errExecEvent := binary.Read(bytes.NewReader(eventBytes), binary.LittleEndian, &execEvent)
	if errExecEvent != nil {
		b.logger.Error(errExecEvent, "Couldn't read event structure")

		return
	}

	b.logger.V(2).Info("eventTypeExecevEnter received", "execEvent", &execEvent)

	var cmdLine string
	for i := range int(execEvent.ArgsLen) {
		cmdLine += strings.ReplaceAll(string(execEvent.Args[i][:]), "\u0000", "") + " "
	}

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
