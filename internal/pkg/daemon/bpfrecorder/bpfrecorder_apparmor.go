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
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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

	// maxTrackedPaths limits the number of unique paths recorded per mount namespace
	// to prevent memory exhaustion (OOM) attacks from malicious workloads.
	maxTrackedPaths = 10000

	// maxTrackedKeys limits the number of distinct workloads tracked to
	// prevent unbounded map growth when many containers start concurrently.
	maxTrackedKeys = 1000
)

var (
	reDirectPathWithPid = regexp.MustCompile(`^/\d+/`)
	reDirectPathWithTid = regexp.MustCompile(`^/@{pid}/task/\d+/`)
	rePathWithPid       = regexp.MustCompile(`^/proc/\d+/`)
	rePathWithTid       = regexp.MustCompile(`^/proc/@{pid}/task/\d+/`)
	rePathWithCid       = regexp.MustCompile(`/var/lib/containers/storage/overlay/\w+/`)
	reUUID              = regexp.MustCompile(
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	)
	reHash          = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
	reDigitSequence = regexp.MustCompile(`\d{6,}`)
)

// recordingKey identifies a group of processes, usually the ones of a
// container. It is the cgroup ID or the mount namespace the BPF program
// reports, see get_key in recorder.bpf.c.
// Note: on a host running concurrent containers, there will be multiple process running with
// the same PID but they are assigned to different keys since they run in different containers.
// Therefore, in order to have unique apparmor profiles, each profile is recorded per key.
type recordingKey uint64

type AppArmorRecorder struct {
	logger      logr.Logger
	programName string
	loaded      bool

	recordedSocketsUse     map[recordingKey]*BpfAppArmorSocketTypes
	lockRecordedSocketsUse sync.Mutex

	recordedCapabilities     map[recordingKey][]int
	lockRecordedCapabilities sync.Mutex

	recordedFiles     map[recordingKey]map[string]*fileAccess
	lockRecordedFiles sync.Mutex

	maxPathsWarned map[recordingKey]bool
	maxKeysWarned  bool

	// excluded holds the keys of workloads which are not recorded. Events
	// for them which are still in flight are dropped.
	excluded     map[recordingKey]struct{}
	lockExcluded sync.RWMutex
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
		programName:              sanitizeFilePath(programName),
		recordedSocketsUse:       map[recordingKey]*BpfAppArmorSocketTypes{},
		lockRecordedSocketsUse:   sync.Mutex{},
		recordedCapabilities:     map[recordingKey][]int{},
		lockRecordedCapabilities: sync.Mutex{},
		recordedFiles:            map[recordingKey]map[string]*fileAccess{},
		lockRecordedFiles:        sync.Mutex{},
		maxPathsWarned:           map[recordingKey]bool{},
		excluded:                 map[recordingKey]struct{}{},
	}
}

// Exclude drops the data recorded for key and ignores its later events.
func (b *AppArmorRecorder) Exclude(key uint64) {
	b.lockExcluded.Lock()
	b.excluded[recordingKey(key)] = struct{}{}
	b.lockExcluded.Unlock()

	b.Clear([]uint64{key})
}

func (b *AppArmorRecorder) isExcluded(key uint64) bool {
	b.lockExcluded.RLock()
	defer b.lockExcluded.RUnlock()

	_, excluded := b.excluded[recordingKey(key)]

	return excluded
}

func (b *AppArmorRecorder) Load(r *BpfRecorder) error {
	if !BPFLSMEnabled() {
		return errors.New("BPF LSM is not enabled for this kernel")
	}

	if err := r.loadPrograms(appArmorHooks); err != nil {
		return fmt.Errorf("load apparmor hooks: %w", err)
	}

	b.loaded = true

	return nil
}

func (b *AppArmorRecorder) StartRecording(r *BpfRecorder) error {
	if !b.loaded {
		return ErrStartBeforeLoad
	}

	return nil
}

func (b *AppArmorRecorder) StopRecording(r *BpfRecorder) error {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	clear(b.recordedSocketsUse)
	clear(b.recordedCapabilities)
	clear(b.recordedFiles)
	clear(b.maxPathsWarned)
	b.maxKeysWarned = false

	b.lockExcluded.Lock()
	clear(b.excluded)
	b.lockExcluded.Unlock()

	return nil
}

func (b *AppArmorRecorder) handleFileEvent(fileEvent *bpfEvent) {
	if b.isExcluded(fileEvent.Key) {
		return
	}

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	fileName := fileDataToString(&fileEvent.Data)

	// A profile only takes absolute paths, a single other one would get the
	// whole recorded profile rejected.
	if !strings.HasPrefix(fileName, "/") {
		b.logger.V(config.VerboseLevel).Info("Skipping file without an absolute path",
			"filename", fileName, "pid", fileEvent.Pid, "key", fileEvent.Key)

		return
	}

	fileName = sanitizeFilePath(fileName)
	fileName = ReplaceVarianceInFilePath(fileName)

	b.logger.V(config.VerboseLevel).Info("File access",
		"filename", fileName, "flags", fileEvent.Flags, "pid", fileEvent.Pid,
		"mntns", fileEvent.Mntns, "key", fileEvent.Key)

	if shouldExcludeFile(fileName) {
		b.logger.V(config.VerboseLevel).Info("Exclude file", "filename", fileName)

		return
	}

	key := recordingKey(fileEvent.Key)
	if _, ok := b.recordedFiles[key]; !ok {
		if len(b.recordedFiles) >= maxTrackedKeys {
			if !b.maxKeysWarned {
				b.logger.Info(
					"Max tracked workloads reached, new containers will not be recorded",
					"limit",
					maxTrackedKeys,
				)
				b.maxKeysWarned = true
			}

			return
		}

		b.recordedFiles[key] = map[string]*fileAccess{}
	}

	// Enforce a limit on max tracked files to avoid OOM.
	if len(b.recordedFiles[key]) >= maxTrackedPaths {
		if !b.maxPathsWarned[key] {
			b.logger.Info("Max tracked files reached, profile will be truncated",
				"key", key, "limit", maxTrackedPaths)
			b.maxPathsWarned[key] = true
		}

		return
	}

	path, ok := b.recordedFiles[key][fileName]
	if !ok {
		path = &fileAccess{}
		b.recordedFiles[key][fileName] = path
	}

	path.read = path.read || ((fileEvent.Flags & flagRead) > 0)
	path.write = path.write || ((fileEvent.Flags & flagWrite) > 0)
	path.exec = path.exec || ((fileEvent.Flags & flagExec) > 0)
	path.spawn = path.spawn || ((fileEvent.Flags & flagSpawn) > 0)
}

func (b *AppArmorRecorder) handleSocketEvent(socketEvent *bpfEvent) {
	if b.isExcluded(socketEvent.Key) {
		return
	}

	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	key := recordingKey(socketEvent.Key)
	if _, ok := b.recordedSocketsUse[key]; !ok {
		b.recordedSocketsUse[key] = &BpfAppArmorSocketTypes{}
	}

	socketType := socketEvent.Flags & sockTypeMask
	switch socketType {
	case sockRaw:
		b.recordedSocketsUse[key].UseRaw = true
	case sockStream:
		b.recordedSocketsUse[key].UseTCP = true
	case sockDgram:
		b.recordedSocketsUse[key].UseUDP = true
	}
}

func (b *AppArmorRecorder) handleCapabilityEvent(capEvent *bpfEvent) {
	if b.isExcluded(capEvent.Key) {
		return
	}

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	key := recordingKey(capEvent.Key)

	requestedCap := int(capEvent.Flags)
	if slices.Contains(b.recordedCapabilities[key], requestedCap) {
		return
	}

	b.logger.Info(
		"Requested capability",
		"capability", capabilityToString(requestedCap),
		"pid", capEvent.Pid,
		"mntns", capEvent.Mntns,
		"key", capEvent.Key,
	)

	b.recordedCapabilities[key] = append(b.recordedCapabilities[key], requestedCap)
}

// clearKey deletes all data recorded for a particular key.
//
// The recorder triggers this after container initialization to make sure that
// permissions needed for setup are not included in the final profile.
func (b *AppArmorRecorder) clearKey(event *bpfEvent) {
	b.logger.Info("Clearing", "key", event.Key)
	b.Clear([]uint64{event.Key})
}

// Clear deletes all data recorded for keys.
func (b *AppArmorRecorder) Clear(keys []uint64) {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	for _, k := range keys {
		key := recordingKey(k)
		delete(b.recordedFiles, key)
		delete(b.recordedCapabilities, key)
		delete(b.recordedSocketsUse, key)
		delete(b.maxPathsWarned, key)
	}
}

// GetKnownKeys returns all keys data got recorded for.
func (b *AppArmorRecorder) GetKnownKeys() []uint64 {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	known := make(map[uint64]struct{}, len(b.recordedFiles))
	for key := range b.recordedFiles {
		known[uint64(key)] = struct{}{}
	}

	for key := range b.recordedCapabilities {
		known[uint64(key)] = struct{}{}
	}

	for key := range b.recordedSocketsUse {
		known[uint64(key)] = struct{}{}
	}

	return slices.Sorted(maps.Keys(known))
}

// GetAppArmorProcessed returns the rules recorded for keys, merged into one
// profile. The data is kept until Clear is called. It reports false if nothing
// was recorded for any of the keys.
func (b *AppArmorRecorder) GetAppArmorProcessed(keys []uint64) (BpfAppArmorProcessed, bool) {
	var processed BpfAppArmorProcessed

	fileProcessed, foundFiles := b.processExecFsEvents(keys)
	processed.FileProcessed = fileProcessed

	foundSockets := false

	b.lockRecordedSocketsUse.Lock()

	for _, k := range keys {
		sockets, ok := b.recordedSocketsUse[recordingKey(k)]
		if !ok || sockets == nil {
			continue
		}

		foundSockets = true
		processed.Socket.UseRaw = processed.Socket.UseRaw || sockets.UseRaw
		processed.Socket.UseTCP = processed.Socket.UseTCP || sockets.UseTCP
		processed.Socket.UseUDP = processed.Socket.UseUDP || sockets.UseUDP
	}

	b.lockRecordedSocketsUse.Unlock()

	capabilities, foundCapabilities := b.processCapabilities(keys)
	processed.Capabilities = capabilities

	return processed, foundFiles || foundSockets || foundCapabilities
}

// deletedSuffix is appended by the kernel to the path of a removed dentry.
const deletedSuffix = " (deleted)"

// sanitizeFilePath replaces every byte the generated AppArmor profile cannot
// carry literally with the `?` glob, which matches any single character. This
// keeps paths like /sys/bus/pci/devices/0000:00:1f.2 in the profile instead of
// failing its validation. Glob and variable characters are replaced as well,
// because AppArmor would interpret them if they were part of a file name. The
// kernel's deleted marker is kept, it is handled when the profile is built.
func sanitizeFilePath(filePath string) string {
	base, suffix := filePath, ""

	// A directory gets a trailing slash after the marker.
	for _, marker := range []string{deletedSuffix, deletedSuffix + "/"} {
		if trimmed, ok := strings.CutSuffix(filePath, marker); ok {
			base, suffix = trimmed, marker
		}
	}

	sanitized := []byte(base)
	for i, c := range sanitized {
		if !isPlainPathByte(c) {
			sanitized[i] = '?'
		}
	}

	return string(sanitized) + suffix
}

func isPlainPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '/', c == '.', c == '_', c == '-', c == '+', c == ' ':
		return true
	default:
		return false
	}
}

func ReplaceVarianceInFilePath(filePath string) string {
	filePath = reDirectPathWithPid.ReplaceAllString(filePath, "/@{pid}/")
	filePath = reDirectPathWithTid.ReplaceAllString(filePath, "/@{pid}/task/@{tid}/")
	filePath = rePathWithPid.ReplaceAllString(filePath, "/proc/@{pid}/")
	filePath = rePathWithTid.ReplaceAllString(filePath, "/proc/@{pid}/task/@{tid}/")
	filePath = rePathWithCid.ReplaceAllString(filePath, "/var/lib/containers/storage/overlay/*/")
	filePath = reUUID.ReplaceAllString(filePath, "*")
	filePath = reHash.ReplaceAllString(filePath, "*")
	filePath = reDigitSequence.ReplaceAllString(filePath, "*")

	if strings.HasPrefix(filePath, "/sys/devices/") {
		filePath = "/sys/devices/**"
	}

	return filePath
}

func shouldExcludeFile(filePath string) bool {
	for _, f := range excludedFilePrefixes {
		if strings.HasPrefix(filePath, f) {
			return true
		}
	}

	return false
}

// fileRule is the access a profile has to allow for a path.
type fileRule struct {
	execute bool
	library bool
	read    bool
	write   bool
}

// processExecFsEvents classifies the file accesses recorded for keys.
func (b *AppArmorRecorder) processExecFsEvents(keys []uint64) (BpfAppArmorFileProcessed, bool) {
	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	var processedEvents BpfAppArmorFileProcessed

	// Every key is classified on its own and the resulting rules are merged,
	// so that a path which one workload writes and another one executes
	// keeps both permissions.
	rules := map[string]fileRule{}
	found := false

	for _, k := range keys {
		files, ok := b.recordedFiles[recordingKey(k)]
		if !ok {
			continue
		}

		found = true

		for fileName, access := range files {
			if processDeletedFiles(fileName, &processedEvents, b.logger) {
				continue
			}

			rule := b.classifyFileAccess(fileName, access)
			merged := rules[fileName]
			merged.execute = merged.execute || rule.execute
			merged.library = merged.library || rule.library
			merged.read = merged.read || rule.read
			merged.write = merged.write || rule.write
			rules[fileName] = merged
		}
	}

	for fileName, rule := range rules {
		switch {
		case rule.execute:
			processedEvents.AllowedExecutables = append(
				processedEvents.AllowedExecutables,
				fileName,
			)
		case rule.library:
			processedEvents.AllowedLibraries = append(processedEvents.AllowedLibraries, fileName)
		}

		// Executing and mapping allow reading. A write only rule would deny
		// the reading, so it becomes a read write rule next to them.
		readable := rule.read || rule.execute || rule.library

		switch {
		case rule.write && readable:
			processedEvents.ReadWritePaths = append(processedEvents.ReadWritePaths, fileName)
		case rule.write:
			processedEvents.WriteOnlyPaths = append(processedEvents.WriteOnlyPaths, fileName)
		case rule.read && !rule.execute && !rule.library:
			processedEvents.ReadOnlyPaths = append(processedEvents.ReadOnlyPaths, fileName)
		}
	}

	// Allow any files in a directory if already at least two files are allowed to have read-write
	// permissions. There are binaries like nginx which typically create files with random name on
	// every start in the /etc/nginx/config.d/ directory. These random named files cannot be captured
	// in advance and allowed in the apparmor profile. This logic SHOULD NOT be applied to read-only
	// files because in that case the file paths are static and should be captured up-front by the
	// recorder. Several keys can add the huge page workaround.
	slices.Sort(processedEvents.ReadWritePaths)
	processedEvents.ReadWritePaths = allowAnyFiles(slices.Compact(processedEvents.ReadWritePaths))

	slices.Sort(processedEvents.AllowedExecutables)
	slices.Sort(processedEvents.AllowedLibraries)
	slices.Sort(processedEvents.ReadOnlyPaths)
	slices.Sort(processedEvents.WriteOnlyPaths)
	slices.Sort(processedEvents.ReadWritePaths)

	return processedEvents, found
}

// classifyFileAccess returns the rule the access of a single workload to a
// file needs. Executing a file takes precedence over any other access of the
// same workload, and accesses the profile already allows through its
// abstractions are left out.
func (b *AppArmorRecorder) classifyFileAccess(fileName string, access *fileAccess) fileRule {
	knownLibrary := isKnownFile(fileName, knownLibrariesPrefixes) || fileName == b.programName
	// The abstractions allow reading and mapping known libraries.
	knownRead := isKnownFile(fileName, knownReadPrefixes) || knownLibrary
	knownWrite := isKnownFile(fileName, knownWritePrefixes)

	switch {
	case access.spawn:
		return fileRule{execute: true}
	case access.exec:
		return fileRule{library: !knownLibrary}
	default:
		return fileRule{
			read:  access.read && !knownRead,
			write: access.write && !knownWrite,
		}
	}
}

// processDeletedFiles process file paths which are marked as deleted by the Linux kernel.
func processDeletedFiles(
	fileName string,
	processedEvents *BpfAppArmorFileProcessed,
	logger logr.Logger,
) bool {
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
		logger.Info("Adding `/` to ReadWritePath as a workaround to enable anonymous huge pages")

		processedEvents.ReadWritePaths = append(processedEvents.ReadWritePaths, "/")

		return true
	}

	// This is returned by the kernel when a dentry is removed.
	// https://github.com/torvalds/linux/blob/2e1b3cc9d7f790145a80cb705b168f05dab65df2/fs/d_path.c#L255-L288
	//
	// It should be ignored since is an invalid path in the apparmor profile.
	if strings.HasSuffix(fileName, deletedSuffix) ||
		strings.HasSuffix(fileName, deletedSuffix+"/") {
		logger.Info("Skipping deleted file", "fileName", fileName)

		return true
	}

	return false
}

// allowAnyFiles allows any file in a directory if more than two files are allowed.
func allowAnyFiles(filePaths []string) []string {
	dupDirs := map[string]int{}

	for _, fp := range filePaths {
		dir := filepath.Dir(fp)
		dupDirs[dir] += 1
	}

	result := []string{}

	for _, fp := range filePaths {
		dir := filepath.Dir(fp)
		if dupDirs[dir] > 1 {
			result = append(result, filepath.Join(dir, "*"))
			dupDirs[dir] = 0
		} else if dupDirs[dir] == 1 {
			result = append(result, fp)
		}
	}

	return result
}

// processCapabilities returns the capabilities recorded for keys.
func (b *AppArmorRecorder) processCapabilities(keys []uint64) ([]string, bool) {
	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	ret := []string{}
	found := false

	for _, k := range keys {
		caps, ok := b.recordedCapabilities[recordingKey(k)]
		if !ok {
			continue
		}

		found = true

		for _, capID := range caps {
			ret = append(ret, capabilityToString(capID))
		}
	}

	slices.Sort(ret)

	return slices.Compact(ret), found
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
