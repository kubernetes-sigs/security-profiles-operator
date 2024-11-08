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

// mntnsID is a unique identifier for a group of processes usually running in a container
// Note: on a host running concurrent containers, there will be multiple process running with
// the same PID but they are assigned to different mntns since  they run in different containers.
// Therefore, in order to have unique apparmor profiles, each profile should be recorded using
// mntns as a key identifier.
type mntnsID uint32

type AppArmorRecorder struct {
	logger      logr.Logger
	programName string

	recordedSocketsUse     map[mntnsID]*BpfAppArmorSocketTypes
	lockRecordedSocketsUse sync.Mutex

	recordedCapabilities     map[mntnsID][]int
	lockRecordedCapabilities sync.Mutex

	recordedFiles     map[mntnsID]map[string]*fileAccess
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
		recordedSocketsUse:       map[mntnsID]*BpfAppArmorSocketTypes{},
		lockRecordedSocketsUse:   sync.Mutex{},
		recordedCapabilities:     map[mntnsID][]int{},
		lockRecordedCapabilities: sync.Mutex{},
		recordedFiles:            map[mntnsID]map[string]*fileAccess{},
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
	fileName = replaceVarianceInFilePath(fileName)

	log.Printf("File access: %s, flags=%d pid=%d mntns=%d\n", fileName, fileEvent.Flags, fileEvent.Pid, fileEvent.Mntns)

	mid := mntnsID(fileEvent.Mntns)
	if _, ok := b.recordedFiles[mid]; !ok {
		b.recordedFiles[mid] = map[string]*fileAccess{}
	}

	path, ok := b.recordedFiles[mid][fileName]
	if !ok {
		path = &fileAccess{}
		b.recordedFiles[mid][fileName] = path
	}

	path.read = path.read || ((fileEvent.Flags & flagRead) > 0)
	path.write = path.write || ((fileEvent.Flags & flagWrite) > 0)
	path.exec = path.exec || ((fileEvent.Flags & flagExec) > 0)
	path.spawn = path.spawn || ((fileEvent.Flags & flagSpawn) > 0)
}

func (b *AppArmorRecorder) handleSocketEvent(socketEvent *bpfEvent) {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	mid := mntnsID(socketEvent.Mntns)
	if _, ok := b.recordedSocketsUse[mid]; !ok {
		b.recordedSocketsUse[mid] = &BpfAppArmorSocketTypes{}
	}
	socketType := socketEvent.Flags & sockTypeMask
	switch socketType {
	case sockRaw:
		b.recordedSocketsUse[mid].UseRaw = true
	case sockStream:
		b.recordedSocketsUse[mid].UseTCP = true
	case sockDgram:
		b.recordedSocketsUse[mid].UseUDP = true
	}
}

func (b *AppArmorRecorder) handleCapabilityEvent(capEvent *bpfEvent) {
	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	mid := mntnsID(capEvent.Mntns)
	if _, ok := b.recordedCapabilities[mid]; !ok {
		b.recordedCapabilities[mid] = []int{}
	}

	requestedCap := int(capEvent.Flags)
	for _, recordedCap := range b.recordedCapabilities[mid] {
		if recordedCap == requestedCap {
			return
		}
	}

	log.Printf(
		"Requested capability: %s with pid=%d, mntns=%d\n",
		capabilityToString(requestedCap),
		capEvent.Pid,
		capEvent.Mntns,
	)
	b.recordedCapabilities[mid] = append(b.recordedCapabilities[mid], requestedCap)
}

func (b *AppArmorRecorder) GetKnownMntns() []mntnsID {
	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()
	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	known := make(map[mntnsID]bool, len(b.recordedFiles))
	for mntns := range b.recordedFiles {
		known[mntns] = true
	}
	for mntns := range b.recordedCapabilities {
		known[mntns] = true
	}
	for mntns := range b.recordedSocketsUse {
		known[mntns] = true
	}

	// Go 1.23: slices.Collect(maps.Keys(known))
	lst := make([]mntnsID, len(known))
	i := 0
	for k := range known {
		lst[i] = k
		i++
	}
	return lst
}

func (b *AppArmorRecorder) GetAppArmorProcessed(mntns uint32) BpfAppArmorProcessed {
	var processed BpfAppArmorProcessed

	mid := mntnsID(mntns)
	processed.FileProcessed = b.processExecFsEvents(mid)
	if sockets, ok := b.recordedSocketsUse[mid]; ok && sockets != nil {
		processed.Socket = *b.recordedSocketsUse[mid]
	}
	processed.Capabilities = b.processCapabilities(mid)

	return processed
}

func replaceVarianceInFilePath(filePath string) string {
	filePath = filepath.Clean(filePath)

	// Replace PID value with a apparmor variable.
	pathWithPid := regexp.MustCompile(`^/proc/\d+/`)
	filePath = pathWithPid.ReplaceAllString(filePath, "/proc/@{pid}/")

	// Replace TID value with a apparmor variable.
	pathWithTid := regexp.MustCompile(`^/proc/@{pid}/task/\d+/`)
	filePath = pathWithTid.ReplaceAllString(filePath, "/proc/@{pid}/task/@{tid}/")

	// Replace container ID with any container ID
	pathWithCid := regexp.MustCompile(`^/var/lib/containers/storage/overlay/\w+/`)
	return pathWithCid.ReplaceAllString(filePath, "/var/lib/containers/storage/overlay/*/")
}

func (b *AppArmorRecorder) processExecFsEvents(mid mntnsID) BpfAppArmorFileProcessed {
	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	var processedEvents BpfAppArmorFileProcessed

	if _, ok := b.recordedFiles[mid]; !ok {
		return processedEvents
	}

	for fileName, access := range b.recordedFiles[mid] {
		// Workaround for HUGETLB support with apparmor:
		// AppArmor treats mmap(..., MAP_ANONYMOUS | MAP_HUGETLB) calls as
		// file access to "", which is then attached to "/" (attach_disconnected).
		// So for HUGETLB to work with AppArmor, we need a `/ rw` rule in our profile.
		// (note that there is no wildcard here - subdirectories/files are not affected).
		// https://gitlab.com/apparmor/apparmor/-/issues/345
		//
		// At the same time, eBPF's bpf_d_path is also slightly confused and reports
		// access to a path named "/anon_hugepage (deleted)" on mmap. Instead of building complex
		// workarounds and hooking mmap, we just treat that as a canary for HUGETLB usage.
		if fileName == "/anon_hugepage (deleted)" {
			processedEvents.ReadWritePaths = append(processedEvents.ReadWritePaths, "/")
			continue
		}

		// This is returned by the kernel when a dentry is removed.
		// https://github.com/torvalds/linux/blob/2e1b3cc9d7f790145a80cb705b168f05dab65df2/fs/d_path.c#L255-L288
		//
		// It should be ignored since is an invalid path in the apparmor profile.
		if fileName == "/ (deleted)" {
			continue
		}

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

func (b *AppArmorRecorder) processCapabilities(mid mntnsID) []string {
	if _, ok := b.recordedCapabilities[mid]; !ok {
		return []string{}
	}
	ret := make([]string, 0, len(b.recordedCapabilities[mid]))
	for _, capID := range b.recordedCapabilities[mid] {
		ret = append(ret, capabilityToString(capID))
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

func capabilityToString(capID int) string {
	val, ok := capabilities[capID]
	if !ok {
		return fmt.Sprintf("CAPABILITY_%d", capID)
	}
	return val
}
