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
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/go-logr/logr"
)

const (
	flagRead     uint64 = 0x1
	flagWrite    uint64 = 0x2
	flagExec     uint64 = 0x4
	flagSpawn    uint64 = 0x8
	sockStream   uint64 = 1
	sockDgram    uint64 = 2
	sockRaw      uint64 = 3
	sockTypeMask uint64 = 0xF
)

var appArmorHooks = []string{
	"file_open",
	"file_lock",
	"mmap_file",
	"bprm_check_security",
	"sys_enter_socket",
	"cap_capable",
}

var pathWithPid *regexp.Regexp = regexp.MustCompile(`^/proc/\d+/`)

type AppArmorRecorder struct {
	logger      logr.Logger
	programName string

	recordedSocketsUse     BpfAppArmorSocketTypes
	lockRecordedSocketsUse sync.Mutex

	recordedCapabilities     []int
	lockRecordedCapabilities sync.Mutex

	recordedFiles     map[string]*fileAccess
	lockRecordedFiles sync.Mutex
}

type fileAccess struct {
	read  bool
	write bool
	exec  bool
	spawn bool
}

type BpfAppArmorSocketTypes struct {
	UseRaw bool
	UseTCP bool
	UseUDP bool
}

type BpfAppArmorProcessed struct {
	FileProcessed BpfAppArmorFileProcessed
	Socket        BpfAppArmorSocketTypes
	Capabilities  []string
}

type BpfAppArmorFileProcessed struct {
	AllowedExecutables []string
	AllowedLibraries   []string
	ReadOnlyPaths      []string
	WriteOnlyPaths     []string
	ReadWritePaths     []string
}

func newAppArmorRecorder(logger logr.Logger, programName string) *AppArmorRecorder {
	return &AppArmorRecorder{
		logger:                   logger,
		programName:              programName,
		recordedSocketsUse:       BpfAppArmorSocketTypes{},
		lockRecordedSocketsUse:   sync.Mutex{},
		recordedCapabilities:     make([]int, 0),
		lockRecordedCapabilities: sync.Mutex{},
		recordedFiles:            make(map[string]*fileAccess),
		lockRecordedFiles:        sync.Mutex{},
	}
}

func (*AppArmorRecorder) Load(b *BpfRecorder) error {
	if !BPFLSMEnabled() {
		return errors.New("BPF LSM is not enabled for this kernel")
	}
	for _, hook := range appArmorHooks {
		if err := b.attachBpfProgram(hook); err != nil {
			return err
		}
	}
	return nil
}

func (b *AppArmorRecorder) Unload() {
}

func (b *AppArmorRecorder) handleFileEvent(fileEvent *bpfEvent) {
	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	fileName := fileDataToString(&fileEvent.Data)

	log.Printf("File access: %s, flags=%d\n", fileName, fileEvent.Flags)

	path, ok := b.recordedFiles[fileName]
	if !ok {
		path = &fileAccess{}
		b.recordedFiles[fileName] = path
	}

	path.read = path.read || ((fileEvent.Flags & flagRead) > 0)
	path.write = path.write || ((fileEvent.Flags & flagWrite) > 0)
	path.exec = path.exec || ((fileEvent.Flags & flagExec) > 0)
	path.spawn = path.spawn || ((fileEvent.Flags & flagSpawn) > 0)
}

func (b *AppArmorRecorder) handleSocketEvent(socketEvent *bpfEvent) {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	socketType := socketEvent.Flags & sockTypeMask
	switch socketType {
	case sockRaw:
		b.recordedSocketsUse.UseRaw = true
	case sockStream:
		b.recordedSocketsUse.UseTCP = true
	case sockDgram:
		b.recordedSocketsUse.UseUDP = true
	}
}

func (b *AppArmorRecorder) handleCapabilityEvent(capEvent *bpfEvent) {
	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	requestedCap := int(capEvent.Flags)

	for _, recordedCap := range b.recordedCapabilities {
		if recordedCap == requestedCap {
			return
		}
	}
	b.recordedCapabilities = append(b.recordedCapabilities, requestedCap)
}

func (b *AppArmorRecorder) GetAppArmorProcessed() BpfAppArmorProcessed {
	var processed BpfAppArmorProcessed

	processed.FileProcessed = b.processExecFsEvents()
	processed.Socket = b.recordedSocketsUse
	processed.Capabilities = b.processCapabilities()

	return processed
}

func (b *AppArmorRecorder) processExecFsEvents() BpfAppArmorFileProcessed {
	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	var processedEvents BpfAppArmorFileProcessed

	for fileName, access := range b.recordedFiles {
		fileName = filepath.Clean(fileName)
		fileName = pathWithPid.ReplaceAllString(fileName, "/proc/@{pid}/")

		knownLibrary := isKnownFile(fileName, knownLibrariesPrefixes) || fileName == b.programName
		knownRead := isKnownFile(fileName, knownReadPrefixes)
		knownWrite := isKnownFile(fileName, knownWritePrefixes)

		if access.spawn { //nolint:gocritic // better readability
			processedEvents.AllowedExecutables = append(processedEvents.AllowedExecutables, fileName)
		} else if access.exec {
			if !knownLibrary {
				processedEvents.AllowedLibraries = append(processedEvents.AllowedLibraries, fileName)
			}
		} else if access.read && access.write {
			// XXX: Condition here isn't exact.
			if !knownRead && !knownWrite && !knownLibrary {
				processedEvents.ReadWritePaths = append(processedEvents.ReadWritePaths, fileName)
			}
		} else if access.read {
			if !knownRead {
				processedEvents.ReadOnlyPaths = append(processedEvents.ReadOnlyPaths, fileName)
			}
		} else if access.write {
			if !knownWrite {
				processedEvents.WriteOnlyPaths = append(processedEvents.WriteOnlyPaths, fileName)
			}
		}
	}

	slices.Sort(processedEvents.AllowedExecutables)
	slices.Sort(processedEvents.AllowedLibraries)
	slices.Sort(processedEvents.ReadOnlyPaths)
	slices.Sort(processedEvents.WriteOnlyPaths)
	slices.Sort(processedEvents.ReadWritePaths)

	return processedEvents
}

func (b *AppArmorRecorder) processCapabilities() []string {
	ret := make([]string, 0, len(b.recordedCapabilities))
	for _, capID := range b.recordedCapabilities {
		val, ok := capabilities[capID]
		if !ok {
			val = fmt.Sprintf("CAPABILITY_%d", capID)
		}
		ret = append(ret, val)
	}
	slices.Sort(ret)
	return ret
}

func fileDataToString(data *[pathMax]uint8) string {
	var eos int
	for i, c := range data {
		if c == 0 {
			eos = i
			break
		}
	}
	return string(data[:eos])
}

func isKnownFile(path string, knownPrefixes []string) bool {
	for _, filter := range knownPrefixes {
		if strings.HasPrefix(path, filter) {
			return true
		}
	}
	return false
}

var capabilities = map[int]string{
	0:  "chown",
	1:  "dac_override",
	2:  "dac_read_search",
	3:  "fowner",
	4:  "fsetid",
	5:  "kill",
	6:  "setgid",
	7:  "setuid",
	8:  "setpcap",
	9:  "linux_immutable",
	10: "net_bind_service",
	11: "net_broadcast",
	12: "net_admin",
	13: "net_raw",
	14: "ipc_lock",
	15: "ipc_owner",
	16: "sys_module",
	17: "sys_rawio",
	18: "sys_chroot",
	19: "sys_ptrace",
	20: "sys_pacct",
	21: "sys_admin",
	22: "sys_boot",
	23: "sys_nice",
	24: "sys_resource",
	25: "sys_time",
	26: "sys_tty_config",
	27: "mknod",
	28: "lease",
	29: "audit_write",
	30: "audit_control",
	31: "setfcap",
	32: "mac_override",
	33: "mac_admin",
	34: "syslog",
	35: "wake_alarm",
	36: "block_suspend",
	37: "audit_read",
	38: "perfmon",
	39: "bpf",
	40: "checkpoint_restore",
}
