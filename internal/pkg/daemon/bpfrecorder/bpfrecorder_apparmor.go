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
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	flagRead     uint64 = 0x1
	flagWrite    uint64 = 0x2
	flagExec     uint64 = 0x4
	flagSpawn    uint64 = 0x8
	flagStat     uint64 = 0x10
	sockStream   uint64 = 1
	sockDgram    uint64 = 2
	sockRaw      uint64 = 3
	sockTypeMask uint64 = 0xF

	// The socket domain is sent in the upper half of the flags.
	sockDomainShift        = 32
	afUnix          uint64 = 1
	afInet          uint64 = 2
	afInet6         uint64 = 10

	// maxTrackedPaths limits the number of unique paths recorded per recording
	// key to prevent memory exhaustion (OOM) attacks from malicious workloads.
	maxTrackedPaths = 10000

	// maxTrackedKeys limits the number of distinct workloads tracked to
	// prevent unbounded map growth when many containers start concurrently.
	maxTrackedKeys = 1000

	// maxProfilePathBytes bounds the path bytes of a single profile. A profile
	// merges the paths of all keys of a recording, and maxTrackedPaths paths
	// of pathMax bytes for each of them would neither fit into a gRPC message
	// nor into an object of the API server, which etcd limits to 1.5 MiB by
	// default. A path can end up in two of the rule lists, and the managed
	// fields of the object list every element of these sets again, which the
	// bound leaves room for below that limit.
	maxProfilePathBytes = 256 * 1024

	// maxNormalizedPaths bounds the cache of normalized file paths.
	maxNormalizedPaths = 4096
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
// reports, see get_key in recorder.bpf.c. The data of a profile is merged from
// the keys of its containers.
type recordingKey uint64

// errBPFLSMDisabled tells that the kernel lacks the BPF LSM the AppArmor hooks
// attach to.
var errBPFLSMDisabled = errors.New("BPF LSM is not enabled for this kernel")

type AppArmorRecorder struct {
	logger      logr.Logger
	programName string
	loaded      bool

	// unavailable tells why the AppArmor hooks are not loaded, set by
	// BpfRecorder.Load before the recorder serves any request.
	unavailable error

	// bpf accesses the maps below, set by Load.
	bpf impl
	// recordedCaps and recordedSockets hold what the BPF program reported
	// already per key, so that it reports every capability and socket once.
	// The entries of a key are dropped with its data, so that they get
	// reported again.
	recordedCaps    *bpf.BPFMap
	recordedSockets *bpf.BPFMap

	// stopped is set while nothing is recording. The events which were still
	// queued when the recording stopped are dropped then, so that they do not
	// take up the keys of the next recording. The handlers check it under
	// the lock of the data they record, which StopRecording holds to set it.
	stopped atomic.Bool

	recordedSocketsUse     map[recordingKey]*BpfAppArmorSocketTypes
	lockRecordedSocketsUse sync.Mutex

	recordedCapabilities     map[recordingKey][]int
	lockRecordedCapabilities sync.Mutex

	recordedFiles     map[recordingKey]map[string]*fileAccess
	lockRecordedFiles sync.Mutex
	// statOnly holds the paths which only got stat'ed so far, which need no
	// rule, see classifyFileAccess. They do not take up the tracked paths of
	// recordedFiles, and are bounded by maxTrackedPaths of their own. Guarded
	// by lockRecordedFiles.
	statOnly map[recordingKey]map[string]struct{}

	// trackedKeys holds the keys data is recorded for, bounded by
	// maxTrackedKeys across files, sockets and capabilities.
	trackedKeys map[recordingKey]struct{}
	// untrackedKeys holds the keys whose capabilities or sockets got
	// reported while no slot was free, bounded by maxTrackedKeys. The BPF
	// program reports them again once a slot frees up, see Clear. Guarded
	// by lockTrackedKeys.
	untrackedKeys   map[recordingKey]struct{}
	lockTrackedKeys sync.Mutex

	maxPathsWarned map[recordingKey]bool
	// maxKeysWarned is guarded by lockTrackedKeys.
	maxKeysWarned bool

	// excluded holds the keys of workloads which are not recorded. Events
	// for them which are still in flight are dropped.
	excluded     map[recordingKey]struct{}
	lockExcluded sync.RWMutex

	// normalizedPaths caches the result of normalizePath per path as the
	// kernel reports it. The same paths are accessed over and over again, and
	// normalizing runs a couple of regular expressions over them.
	normalizedPaths     map[string]normalizedPath
	lockNormalizedPaths sync.Mutex
}

// normalizedPath is a path as it goes into the profile.
type normalizedPath struct {
	path     string
	excluded bool
}

type fileAccess struct {
	read  bool
	write bool
	exec  bool
	spawn bool
	// stat is set if the attributes of the file got read, which AppArmor
	// checks read access for, see classifyFileAccess.
	stat bool
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

// SetProgramPath sets the absolute path of the executable of the recorded
// program, which is left out of the recorded libraries. The program name
// passed to New filters the processes by their comm instead, the base name of
// the path the program got started with, whose symlinks are not resolved.
func (b *AppArmorRecorder) SetProgramPath(path string) {
	b.programName = sanitizeFilePath(path)
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
		statOnly:                 map[recordingKey]map[string]struct{}{},
		lockRecordedFiles:        sync.Mutex{},
		trackedKeys:              map[recordingKey]struct{}{},
		untrackedKeys:            map[recordingKey]struct{}{},
		maxPathsWarned:           map[recordingKey]bool{},
		excluded:                 map[recordingKey]struct{}{},
		normalizedPaths:          map[string]normalizedPath{},
	}
}

// maxExcludedKeys bounds the excluded keys like the exclude_keys map of the
// BPF program, which holds as many.
const maxExcludedKeys = 32 * 1024

// Exclude drops the data recorded for key and ignores its later events.
//
// The excluded keys are only pruned for cgroup keys, see
// pruneRemovedCgroups, so they are bounded otherwise. The BPF program
// forgets its oldest excluded keys as well and reports a workload whose key
// got forgotten again, which excludes it again.
func (b *AppArmorRecorder) Exclude(key uint64) {
	b.lockExcluded.Lock()

	if _, ok := b.excluded[recordingKey(key)]; !ok && len(b.excluded) >= maxExcludedKeys {
		for excluded := range b.excluded {
			delete(b.excluded, excluded)

			break
		}
	}

	b.excluded[recordingKey(key)] = struct{}{}
	b.lockExcluded.Unlock()

	b.Clear([]uint64{key})
}

// Unexclude forgets an excluded key, whose workload is gone.
func (b *AppArmorRecorder) Unexclude(key uint64) {
	b.lockExcluded.Lock()
	delete(b.excluded, recordingKey(key))
	b.lockExcluded.Unlock()
}

func (b *AppArmorRecorder) isExcluded(key uint64) bool {
	b.lockExcluded.RLock()
	defer b.lockExcluded.RUnlock()

	_, excluded := b.excluded[recordingKey(key)]

	return excluded
}

// Load attaches the AppArmor hooks. On error, the hooks which got attached
// already are detached again, so that the recorder can go on without them.
func (b *AppArmorRecorder) Load(r *BpfRecorder) error {
	if !r.wantAppArmor() {
		return errBPFLSMDisabled
	}

	links, err := r.attachPrograms(appArmorHooks)
	if err != nil {
		r.detachLinks(links)

		return fmt.Errorf("load apparmor hooks: %w", err)
	}

	bpfMaps := map[string]*bpf.BPFMap{}

	for _, name := range []string{mapRecordedCaps, mapRecordedSockets} {
		bpfMap, err := r.GetMap(r.module, name)
		if err != nil {
			r.detachLinks(links)

			return fmt.Errorf("getting `%s` map: %w", name, err)
		}

		bpfMaps[name] = bpfMap
	}

	b.recordedCaps = bpfMaps[mapRecordedCaps]
	b.recordedSockets = bpfMaps[mapRecordedSockets]
	b.bpf = r.impl
	b.loaded = true

	return nil
}

// disable marks AppArmor recording as unavailable for the provided reason.
func (b *AppArmorRecorder) disable(reason error) {
	b.unavailable = reason
	b.loaded = false
}

// Unavailable returns why AppArmor profiles cannot be recorded, or nil if
// nothing is known to prevent it. The error wraps ErrAppArmorUnavailable.
func (b *AppArmorRecorder) Unavailable() error {
	if b.unavailable == nil {
		return nil
	}

	return fmt.Errorf("%w: %w", ErrAppArmorUnavailable, b.unavailable)
}

// unload forgets the maps of the module. The event handlers use them while
// they hold the lock of their kind, see forgetReported, so both are held.
func (b *AppArmorRecorder) unload() {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	b.recordedCaps = nil
	b.recordedSockets = nil
	b.loaded = false
}

func (b *AppArmorRecorder) StartRecording(r *BpfRecorder) error {
	if !b.loaded {
		return ErrStartBeforeLoad
	}

	// Under the locks of StopRecording, like setting it, so that a handler
	// sees the state of one recording while it holds its lock.
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	b.stopped.Store(false)

	return nil
}

func (b *AppArmorRecorder) StopRecording(r *BpfRecorder) error {
	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	b.stopped.Store(true)

	clear(b.recordedSocketsUse)
	clear(b.recordedCapabilities)
	clear(b.recordedFiles)
	clear(b.statOnly)
	clear(b.maxPathsWarned)

	b.lockTrackedKeys.Lock()
	clear(b.trackedKeys)
	clear(b.untrackedKeys)
	b.maxKeysWarned = false
	b.lockTrackedKeys.Unlock()

	b.lockExcluded.Lock()
	clear(b.excluded)
	b.lockExcluded.Unlock()

	b.lockNormalizedPaths.Lock()
	clear(b.normalizedPaths)
	b.lockNormalizedPaths.Unlock()

	// The kernel side is not maintained while nothing is recording. Both
	// maps are cleared even if clearing one fails.
	var errs []error

	for _, bpfMap := range []*bpf.BPFMap{b.recordedCaps, b.recordedSockets} {
		if err := clearBpfMap(r, bpfMap); err != nil {
			errs = append(errs, fmt.Errorf("clear reported capabilities and sockets: %w", err))
		}
	}

	return errors.Join(errs...)
}

// trackKey reports whether data can be recorded for key. The number of keys
// tracked at once is bounded across files, sockets and capabilities, so that
// many containers starting at once cannot grow the maps without bounds.
//
// The caller holds the lock of the data it records and checked that the key
// is not excluded while holding it. Exclude clears the data, which takes that
// lock, only after it marked the key, so an excluded key is either seen as
// such or its data and slot get cleared after they were recorded.
func (b *AppArmorRecorder) trackKey(key recordingKey) bool {
	b.lockTrackedKeys.Lock()
	defer b.lockTrackedKeys.Unlock()

	if _, ok := b.trackedKeys[key]; ok {
		return true
	}

	if len(b.trackedKeys) >= maxTrackedKeys {
		if !b.maxKeysWarned {
			b.logger.Info(
				"Max tracked workloads reached, new containers will not be recorded",
				"limit",
				maxTrackedKeys,
			)
			b.maxKeysWarned = true
		}

		return false
	}

	b.trackedKeys[key] = struct{}{}

	return true
}

// skipUntracked handles a capability or socket of a key which trackKey
// rejected. The BPF program reports each of them only once per key, so it
// has to report them again once the key can be tracked. Until a slot frees
// up, see Clear, the key stays reported in the kernel, which keeps its events
// from crowding out the ones of the tracked keys.
func (b *AppArmorRecorder) skipUntracked(key recordingKey) {
	b.lockTrackedKeys.Lock()
	defer b.lockTrackedKeys.Unlock()

	if _, ok := b.untrackedKeys[key]; ok {
		return
	}

	if len(b.untrackedKeys) < maxTrackedKeys {
		b.untrackedKeys[key] = struct{}{}

		return
	}

	// Too many keys wait for a slot already, so this one gets reported
	// again right away.
	b.forgetReported([]uint64{uint64(key)})
}

// normalizePath returns the path the profile gets for a path the kernel
// reported, and whether it is left out of the profile.
func (b *AppArmorRecorder) normalizePath(raw []byte) normalizedPath {
	b.lockNormalizedPaths.Lock()
	defer b.lockNormalizedPaths.Unlock()

	// The lookup with the converted bytes does not allocate, which matters
	// as this runs for every file event.
	if normalized, ok := b.normalizedPaths[string(raw)]; ok {
		return normalized
	}

	fileName := string(raw)

	path := ReplaceVarianceInFilePath(sanitizeFilePath(fileName))
	normalized := normalizedPath{path: path, excluded: shouldExcludeFile(path)}

	// Paths with PIDs or random names keep coming, so the cache starts over
	// instead of growing without bounds.
	if len(b.normalizedPaths) >= maxNormalizedPaths {
		clear(b.normalizedPaths)
	}

	b.normalizedPaths[fileName] = normalized

	return normalized
}

func (b *AppArmorRecorder) handleFileEvent(fileEvent *bpfEvent) {
	if b.isExcluded(fileEvent.Key) {
		return
	}

	raw := fileData(fileEvent.Data)

	// A profile only takes absolute paths, a single other one would get the
	// whole recorded profile rejected.
	if !bytes.HasPrefix(raw, []byte{'/'}) {
		b.logger.V(config.VerboseLevel).Info("Skipping file without an absolute path",
			"filename", string(raw), "pid", fileEvent.Pid, "key", fileEvent.Key)

		return
	}

	normalized := b.normalizePath(raw)
	fileName := normalized.path

	// This runs for every file event, so the arguments are only built if the
	// line gets logged.
	if verbose := b.logger.V(config.VerboseLevel); verbose.Enabled() {
		verbose.Info("File access",
			"filename", fileName, "flags", fileEvent.Flags, "pid", fileEvent.Pid,
			"mntns", fileEvent.Mntns, "key", fileEvent.Key)
	}

	if normalized.excluded {
		b.logger.V(config.VerboseLevel).Info("Exclude file", "filename", fileName)

		return
	}

	key := recordingKey(fileEvent.Key)

	b.lockRecordedFiles.Lock()
	defer b.lockRecordedFiles.Unlock()

	// The key may have been excluded since the check above, see trackKey.
	if b.stopped.Load() || b.isExcluded(fileEvent.Key) || !b.trackKey(key) {
		return
	}

	path, ok := b.recordedFiles[key][fileName]
	if !ok && fileEvent.Flags == flagStat {
		// A stat alone needs no rule, it only matters for a later access
		// of the path, see classifyFileAccess. Stat heavy workloads, like
		// a module resolution walking many directories, would truncate the
		// rules otherwise.
		b.recordStat(key, fileName)

		return
	}

	if _, ok := b.recordedFiles[key]; !ok {
		b.recordedFiles[key] = map[string]*fileAccess{}
	}

	if !ok {
		// Enforce a limit on max tracked files to avoid OOM. The paths which
		// are tracked already still gather their access flags.
		if len(b.recordedFiles[key]) >= maxTrackedPaths {
			if !b.maxPathsWarned[key] {
				b.logger.Info("Max tracked files reached, profile will be truncated",
					"key", key, "limit", maxTrackedPaths)
				b.maxPathsWarned[key] = true
			}

			return
		}

		_, stat := b.statOnly[key][fileName]
		delete(b.statOnly[key], fileName)

		path = &fileAccess{stat: stat}
		b.recordedFiles[key][fileName] = path
	}

	path.read = path.read || ((fileEvent.Flags & flagRead) > 0)
	path.write = path.write || ((fileEvent.Flags & flagWrite) > 0)
	path.exec = path.exec || ((fileEvent.Flags & flagExec) > 0)
	path.spawn = path.spawn || ((fileEvent.Flags & flagSpawn) > 0)
	path.stat = path.stat || ((fileEvent.Flags & flagStat) > 0)
}

// recordStat remembers that the path only got stat'ed so far. A path beyond
// maxTrackedPaths is not remembered, a later write of it gets a write only
// rule then. It has to be called with lockRecordedFiles held.
func (b *AppArmorRecorder) recordStat(key recordingKey, fileName string) {
	paths, ok := b.statOnly[key]
	if !ok {
		paths = map[string]struct{}{}
		b.statOnly[key] = paths
	}

	if len(paths) < maxTrackedPaths {
		paths[fileName] = struct{}{}
	}
}

func (b *AppArmorRecorder) handleSocketEvent(socketEvent *bpfEvent) {
	var use BpfAppArmorSocketTypes
	if !socketUse(socketEvent.Flags, &use) {
		return
	}

	key := recordingKey(socketEvent.Key)

	b.lockRecordedSocketsUse.Lock()
	defer b.lockRecordedSocketsUse.Unlock()

	// Checked under the lock, see trackKey.
	if b.stopped.Load() || b.isExcluded(socketEvent.Key) {
		return
	}

	if !b.trackKey(key) {
		b.skipUntracked(key)

		return
	}

	if _, ok := b.recordedSocketsUse[key]; !ok {
		b.recordedSocketsUse[key] = &BpfAppArmorSocketTypes{}
	}

	recorded := b.recordedSocketsUse[key]
	recorded.UseRaw = recorded.UseRaw || use.UseRaw
	recorded.UseTCP = recorded.UseTCP || use.UseTCP
	recorded.UseUDP = recorded.UseUDP || use.UseUDP
}

// socketUse sets the network rule a socket with the domain and type in flags
// needs in use. It reports false if the socket needs none of them.
//
// The tcp and udp rules only cover the internet domains. The raw rule allows
// raw sockets of any domain, so the raw sockets of the others, like the netlink
// ones, still need it. Unix domain sockets are not covered by network rules.
func socketUse(flags uint64, use *BpfAppArmorSocketTypes) bool {
	domain := flags >> sockDomainShift
	socketType := flags & sockTypeMask

	if socketType == sockRaw && domain != afUnix {
		use.UseRaw = true

		return true
	}

	if domain != afInet && domain != afInet6 {
		return false
	}

	switch socketType {
	case sockStream:
		use.UseTCP = true
	case sockDgram:
		use.UseUDP = true
	default:
		return false
	}

	return true
}

func (b *AppArmorRecorder) handleCapabilityEvent(capEvent *bpfEvent) {
	key := recordingKey(capEvent.Key)

	b.lockRecordedCapabilities.Lock()
	defer b.lockRecordedCapabilities.Unlock()

	// Checked under the lock, see trackKey.
	if b.stopped.Load() || b.isExcluded(capEvent.Key) {
		return
	}

	if !b.trackKey(key) {
		b.skipUntracked(key)

		return
	}

	requestedCap := int(capEvent.Flags) //nolint:gosec // a capability number, see CAP_LAST_CAP
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

	b.lockTrackedKeys.Lock()
	defer b.lockTrackedKeys.Unlock()

	freed := false

	for _, k := range keys {
		key := recordingKey(k)
		delete(b.recordedFiles, key)
		delete(b.statOnly, key)
		delete(b.recordedCapabilities, key)
		delete(b.recordedSocketsUse, key)
		delete(b.maxPathsWarned, key)
		delete(b.untrackedKeys, key)

		if _, ok := b.trackedKeys[key]; ok {
			delete(b.trackedKeys, key)

			freed = true
		}
	}

	// The keys waiting for a slot get reported again, the ones which do
	// not get one wait again.
	reported := keys
	if freed && len(b.untrackedKeys) > 0 {
		reported = slices.Clone(keys)
		for key := range b.untrackedKeys {
			reported = append(reported, uint64(key))
		}

		clear(b.untrackedKeys)
	}

	b.forgetReported(reported)
}

// forgetReported makes the BPF program report the capabilities and sockets of
// keys again, their data is gone here.
func (b *AppArmorRecorder) forgetReported(keys []uint64) {
	if b.bpf == nil {
		return
	}

	for _, bpfMap := range []*bpf.BPFMap{b.recordedCaps, b.recordedSockets} {
		if bpfMap == nil {
			continue
		}

		for _, key := range keys {
			err := b.bpf.DeleteKey64(bpfMap, key)
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				b.logger.Error(err, "Unable to reset reported capabilities and sockets", "key", key)
			}
		}
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

	// A key which only stat'ed files is known as well, so that its data
	// gets swept with it.
	for key := range b.statOnly {
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
	return isKnownFile(filePath, excludedFilePrefixes)
}

// fileRule is the access a profile has to allow for a path.
type fileRule struct {
	execute bool
	library bool
	read    bool
	write   bool
	// reads is set if the file got read, executed or mapped executable, and
	// writes if it got written, even if the abstractions allow that already.
	// They emit no rule on their own, but the read only and write only rules
	// deny the other access, which must not take away what got used.
	reads  bool
	writes bool
}

// merge returns the rule which allows the access of both rules.
func (r fileRule) merge(other fileRule) fileRule {
	return fileRule{
		execute: r.execute || other.execute,
		library: r.library || other.library,
		read:    r.read || other.read,
		write:   r.write || other.write,
		reads:   r.reads || other.reads,
		writes:  r.writes || other.writes,
	}
}

// emits reports whether the rule needs a rule of the profile on its own, see
// processExecFsEvents. A rule which only reads or writes, like for a path the
// abstractions allow, changes a rule of the same path of another key at most.
func (r fileRule) emits() bool {
	return r.execute || r.library || r.read || r.write
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
	pathBytes := 0
	charged := map[string]bool{}
	truncated := false

	for _, k := range keys {
		files, ok := b.recordedFiles[recordingKey(k)]
		if !ok {
			continue
		}

		found = true

		// Sorted, so that a truncated profile always keeps the same paths.
		for _, fileName := range slices.Sorted(maps.Keys(files)) {
			if processDeletedFiles(fileName, &processedEvents, b.logger) {
				continue
			}

			merged := rules[fileName].merge(b.classifyFileAccess(fileName, files[fileName]))

			// Only the paths which get a rule take up the size of the
			// profile, the ones the abstractions allow do not.
			if merged.emits() && !charged[fileName] {
				if pathBytes+len(fileName) > maxProfilePathBytes {
					truncated = true

					continue
				}

				pathBytes += len(fileName)
				charged[fileName] = true
			}

			rules[fileName] = merged
		}
	}

	if truncated {
		b.logger.Info("Recorded paths exceed the size of a profile, profile will be truncated",
			"keys", keys, "limit", maxProfilePathBytes)
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
		// the reading, so it becomes a read write rule next to them, like
		// next to a read the abstractions allow. A read only rule would deny
		// a write the abstractions allow in the same way.
		readable := rule.read || rule.execute || rule.library || rule.reads

		switch {
		case rule.write && readable:
			processedEvents.ReadWritePaths = append(processedEvents.ReadWritePaths, fileName)
		case rule.write:
			processedEvents.WriteOnlyPaths = append(processedEvents.WriteOnlyPaths, fileName)
		case rule.read && !rule.execute && !rule.library && rule.writes:
			processedEvents.ReadWritePaths = append(processedEvents.ReadWritePaths, fileName)
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
// file needs. Executing a file takes precedence over mapping it, a write of
// the same workload is kept next to both, like the one of another workload,
// see processExecFsEvents. Accesses the profile already allows through its
// abstractions are left out.
func (b *AppArmorRecorder) classifyFileAccess(fileName string, access *fileAccess) fileRule {
	knownLibrary := isKnownFile(fileName, knownLibrariesPrefixes) || fileName == b.programName
	// The abstractions allow reading and mapping known libraries.
	knownRead := isKnownFile(fileName, knownReadPrefixes) || knownLibrary
	knownWrite := isKnownFile(fileName, knownWritePrefixes)

	rule := fileRule{write: access.write && !knownWrite, writes: access.write}

	switch {
	case access.spawn:
		rule.execute = true
		rule.reads = true
	case access.exec:
		rule.library = !knownLibrary
		rule.reads = true
	default:
		rule.read = access.read && !knownRead
		rule.reads = access.read
	}

	// A stat needs read access, but no rule of its own: a path which only
	// got stat'ed, like an inherited /dev/null, would get a read only rule
	// otherwise, which denies the writes the abstractions allow. It keeps a
	// write only rule from denying the read. Known limitation: a path which
	// only gets stat'ed, and which the abstractions do not allow, has no rule
	// in the recorded profile, so the stat gets denied once it is enforced.
	rule.reads = rule.reads || access.stat

	return rule
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

// allowAnyFiles allows any file in a directory if at least two files of it are
// allowed. A file which got stat'ed and written counts as read write as well,
// so it can make a directory collapse into the glob too. Directories, which
// the recorder reports with a trailing slash, are kept as they are: the glob of
// the files in a directory does not match the directory itself, which creating
// it needs. The files of noGlob are kept as they are as well.
func allowAnyFiles(filePaths []string) []string {
	dupDirs := map[string]int{}

	for _, fp := range filePaths {
		if strings.HasSuffix(fp, "/") || noGlob(fp) {
			continue
		}

		dupDirs[filepath.Dir(fp)]++
	}

	result := []string{}

	for _, fp := range filePaths {
		if strings.HasSuffix(fp, "/") || noGlob(fp) {
			result = append(result, fp)

			continue
		}

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

// fileData returns the path of the data of a file event. The BPF program
// sends the path with its terminating NUL byte and nothing after it.
func fileData(data []byte) []byte {
	return bytes.TrimSuffix(data, []byte{0})
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
