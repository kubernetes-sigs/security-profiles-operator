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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	defaultTimeout          time.Duration = time.Minute
	maxMsgSize              int           = 16 * 1024 * 1024
	maxCommLen              int           = 64
	defaultCacheTimeout     time.Duration = time.Hour
	maxNewPidHandlers       int           = 32
	newPidQueueSize         int           = 1024
	maxCacheItems           uint64        = 1000
	defaultHostPid          uint32        = 1
	pathMax                 int           = 4096
	eventTypeNewPid         int           = 0
	eventTypeExit           int           = 1
	eventTypeAppArmorFile   int           = 2
	eventTypeAppArmorSocket int           = 3
	eventTypeAppArmorCap    int           = 4
	eventTypeClearMntns     int           = 5
	eventTypeExecveEnter    uint8         = 6
	excludeMntnsEnabled     byte          = 1

	// lostEventsInterval is how often the kernel side drop counters are
	// checked while a recording is running.
	lostEventsInterval = 30 * time.Second
)

// Indexes of the lost_events map, see recorder.bpf.c.
const (
	lostRingbuf uint32 = iota
	lostSyscallsMapFull
	lostFileEventBusy
	lostReasons
)

// BpfRecorder is the main structure of this package.
type BpfRecorder struct {
	api.UnimplementedBpfRecorderServer
	impl
	logger                  logr.Logger
	startRequests           int64
	btfPath                 string
	pidToContainerIDCache   *ttlcache.Cache[string, string]
	containerKeys           *containerKeys
	containerIDToProfileMap *containerProfiles
	// collectedProfiles holds the profiles whose data was reset after they had
	// been persisted, so that a retried collection is told right away that
	// there is nothing left to collect.
	collectedProfiles sync.Map
	// containersWithoutProfile remembers container IDs that were found in the
	// cluster but carry no recording annotation. Without it every event from
	// every unannotated container on the node triggers a fresh node-wide pod
	// list, because only positive lookups were cached.
	containersWithoutProfile *ttlcache.Cache[string, struct{}]
	nodeName                 string
	clientset                *kubernetes.Clientset
	excludeMountNamespace    uint32
	attachUnattachMutex      sync.RWMutex
	metrics                  *metrics.Sender[*apimetrics.BpfRequest]
	programName              string
	module                   *bpf.Module
	isRecordingBpfMap        *bpf.BPFMap
	activePidsBpfMap         *bpf.BPFMap
	childPidsBpfMap          *bpf.BPFMap
	excludeKeysBpfMap        *bpf.BPFMap
	seccompInitBpfMap        *bpf.BPFMap
	apparmorInitBpfMap       *bpf.BPFMap
	lostEventsBpfMap         *bpf.BPFMap
	// lostEvents holds the drop counters last reported, guarded by
	// lostEventsMu.
	lostEvents   [lostReasons]uint64
	lostEventsMu sync.Mutex
	// uniqueKeys is set if the BPF program stores the recorded data under
	// keys which are never reused.
	uniqueKeys bool

	AppArmor *AppArmorRecorder
	Seccomp  *SeccompRecorder

	startMu sync.Mutex

	// newPidEvents queues new pid events for a fixed pool of handlers. It is
	// buffered so that the event processing loop never blocks on a slow
	// handler: that loop also delivers the AppArmor events, so stalling it
	// back pressures the ring buffer and makes the kernel drop recorded
	// events. It is bounded so that a fork heavy workload cannot grow the
	// queue until the recorder is out of memory.
	newPidEvents     chan newPidEvent
	startPidHandlers sync.Once

	// recordingGeneration is bumped whenever a recording session ends. Handlers
	// carry the generation their event was queued in and skip writing to the
	// lookup tables once it no longer matches, so a handler still in flight
	// cannot repopulate the tables after they were released.
	recordingGeneration atomic.Uint64

	// recentExits bounds how many exited PIDs are remembered so that
	// WaitForPidExit can observe an exit that happened just before it started
	// waiting. In-cluster nobody waits for those PIDs, so an unbounded map
	// would leak an entry per recorded process exit.
	recentExits *ttlcache.Cache[uint32, struct{}]

	// exitWaiters holds a channel per caller currently inside WaitForPidExit.
	// Waiters own their channel and remove it themselves, so it is bounded by
	// the number of concurrent waiters and can never be evicted from under a
	// parked caller.
	exitWaiters sync.Map
}

// newPidEvent is the queued form of a new pid event.
type newPidEvent struct {
	pid        uint32
	mntns      uint32
	key        uint64
	generation uint64
}

// We use a single shared event ringbuf for all userspace communication.
// This ensures that all previous events have already been processed.
//
// Key is the key the recorded data is stored under, the cgroup ID or the mount
// namespace, see get_key in recorder.bpf.c.
type bpfEvent struct {
	Pid   uint32
	Mntns uint32
	Key   uint64
	Type  uint8
	Flags uint64
	Data  [pathMax]uint8
}

var errShortEvent = errors.New("event shorter than the expected structure")

const (
	// bpfEventHeaderSize is the packed wire size of the event header, matching
	// the packed C struct in recorder.bpf.c. encoding/binary inserts no
	// padding, so this is simply the sum of the field widths.
	bpfEventHeaderSize = 4 + 4 + 8 + 1 + 8

	// bpfEventSize is the size of the largest event. Events without data are
	// only sent as the header, file events only with the used part of Data.
	bpfEventSize = bpfEventHeaderSize + pathMax
)

// unmarshalHeader decodes the event header shared by all events.
func unmarshalHeader(raw []byte) (pid, mntns uint32, key uint64, typ uint8, flags uint64) {
	return binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint32(raw[4:8]),
		binary.LittleEndian.Uint64(raw[8:16]),
		raw[16],
		binary.LittleEndian.Uint64(raw[17:25])
}

// unmarshal decodes a bpfEvent from the raw ring buffer bytes. This is a manual
// decode on purpose: binary.Read reflects over the 4096-byte Data array for
// every single event, which costs ~240x more than reading the fields directly
// and is hot enough on a busy node to make the ring buffer drop events.
func (e *bpfEvent) unmarshal(raw []byte) bool {
	if len(raw) < bpfEventHeaderSize {
		return false
	}

	e.Pid, e.Mntns, e.Key, e.Type, e.Flags = unmarshalHeader(raw)
	n := copy(e.Data[:], raw[bpfEventHeaderSize:])
	clear(e.Data[n:])

	return true
}

// New returns a new BpfRecorder instance.
func New(programName string, logger logr.Logger, recordSeccomp, recordAppArmor bool) *BpfRecorder {
	var seccomp *SeccompRecorder
	if recordSeccomp {
		seccomp = newSeccompRecorder(logger)
	}

	var appArmor *AppArmorRecorder
	if recordAppArmor {
		appArmor = newAppArmorRecorder(logger, programName)
	}

	return &BpfRecorder{
		impl:   &defaultImpl{},
		logger: logger,

		pidToContainerIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		containerKeys:           newContainerKeys(),
		containerIDToProfileMap: newContainerProfiles(),
		containersWithoutProfile: ttlcache.New(
			ttlcache.WithTTL[string, struct{}](defaultCacheTimeout),
			ttlcache.WithCapacity[string, struct{}](maxCacheItems),
			ttlcache.WithDisableTouchOnHit[string, struct{}](),
		),
		attachUnattachMutex: sync.RWMutex{},
		programName:         programName,
		AppArmor:            appArmor,
		Seccomp:             seccomp,
		newPidEvents:        make(chan newPidEvent, newPidQueueSize),
		recentExits: ttlcache.New(
			ttlcache.WithTTL[uint32, struct{}](defaultCacheTimeout),
			ttlcache.WithCapacity[uint32, struct{}](maxCacheItems),
			ttlcache.WithDisableTouchOnHit[uint32, struct{}](),
		),
	}
}

// Syscalls returns the bpf map containing the PID (key) to syscalls (value)
// data.
func (b *BpfRecorder) Syscalls() *bpf.BPFMap {
	return b.Seccomp.syscalls
}

// Run the BpfRecorder.
func (b *BpfRecorder) Run() error {
	b.logger.Info("Setting up caches", "expiry", defaultCacheTimeout)

	go b.pidToContainerIDCache.Start()
	defer b.pidToContainerIDCache.Stop()

	go b.recentExits.Start()
	defer b.recentExits.Stop()

	go b.containersWithoutProfile.Start()
	defer b.containersWithoutProfile.Stop()

	if b.nodeName == "" {
		b.nodeName = os.Getenv(config.NodeNameEnvKey)
	}

	if b.nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		b.logger.Error(err, "unable to run recorder")

		return err
	}

	b.logger.Info("Starting ebpf recorder on node", "node", b.nodeName)

	clusterConfig, err := b.InClusterConfig()
	if err != nil {
		return fmt.Errorf("get in-cluster config: %w", err)
	}

	b.clientset, err = b.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("load in-cluster client: %w", err)
	}

	if _, err := b.Stat(config.GRPCServerSocketBpfRecorder); err == nil {
		if err := b.RemoveAll(config.GRPCServerSocketBpfRecorder); err != nil {
			return fmt.Errorf("remove GRPC socket file: %w", err)
		}
	}

	listener, err := b.Listen("unix", config.GRPCServerSocketBpfRecorder)
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}

	if err := b.Chown(
		config.GRPCServerSocketBpfRecorder,
		config.UserRootless,
		config.UserRootless,
	); err != nil {
		return fmt.Errorf("change GRPC socket owner to rootless: %w", err)
	}

	b.logger.Info("Connecting to metrics server")

	if err := b.connectMetrics(); err != nil {
		return fmt.Errorf("connect to metrics server: %w", err)
	}

	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	defer stopMetrics()

	go b.metrics.Run(metricsCtx)

	b.excludeMountNamespace, err = b.FindProcMountNamespace(defaultHostPid)
	if err != nil {
		return fmt.Errorf("retrieve current mount namespace: %w", err)
	}

	b.logger.Info(
		"Got system mount namespace: " + strconv.FormatUint(uint64(b.excludeMountNamespace), 10),
	)

	if _, err := b.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		b.logger.Info(
			"WARNING: /sys/kernel/btf/vmlinux not found, BPF recording will not work on this kernel",
		)
	}

	b.logger.Info("Loading BPF program")

	if err := b.Load(); err != nil {
		return fmt.Errorf("bpf load: %w", err)
	}

	b.logger.Info("Doing BPF start/stop self-test...")

	if err := b.StartRecording(); err != nil {
		return fmt.Errorf("StartRecording self-test: %w", err)
	}

	if err := b.StopRecording(); err != nil {
		return fmt.Errorf("StopRecording self-test: %w", err)
	}

	b.logger.Info("BPF start/stop self-test successful.")

	b.logger.Info("Starting GRPC API server")

	grpcServer := grpc.NewServer(
		grpc.MaxSendMsgSize(maxMsgSize),
		grpc.MaxRecvMsgSize(maxMsgSize),
	)
	api.RegisterBpfRecorderServer(grpcServer, b)

	return b.Serve(grpcServer, listener)
}

// connectMetrics sets up the metrics sender and waits for the initial stream,
// so that a daemon which cannot reach the metrics server at all fails early.
// The sender re-opens the stream on its own if it breaks later on.
func (b *BpfRecorder) connectMetrics() error {
	b.metrics = metrics.NewSender(b.logger, metrics.DefaultSenderQueueSize, b.openMetricsStream)

	if err := util.Retry(b.metrics.Connect, func(error) bool { return true }); err != nil {
		return fmt.Errorf("connect to local GRPC server: %w", err)
	}

	return nil
}

// bpfMetricsStream sends through the impl, so that tests can fake the stream.
type bpfMetricsStream struct {
	b      *BpfRecorder
	client apimetrics.Metrics_BpfIncClient
}

func (s bpfMetricsStream) Send(req *apimetrics.BpfRequest) error {
	return s.b.SendMetric(s.client, req)
}

func (b *BpfRecorder) openMetricsStream() (metrics.Stream[*apimetrics.BpfRequest], func(), error) {
	conn, err := b.DialMetrics()
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to local metrics GRPC server: %w", err)
	}

	release := func() {
		if err := b.CloseGRPC(conn); err != nil {
			b.logger.Error(err, "Unable to close GRPC connection")
		}
	}

	client, err := b.BpfIncClient(apimetrics.NewMetricsClient(conn))
	if err != nil {
		release()

		return nil, nil, fmt.Errorf("create metrics bpf client: %w", err)
	}

	return bpfMetricsStream{b: b, client: client}, release, nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+config.GRPCServerSocketBpfRecorder,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("GRPC dial: %w", err)
	}

	return conn, nil
}

func (b *BpfRecorder) Start(
	context.Context, *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	b.startMu.Lock()
	defer b.startMu.Unlock()

	if atomic.LoadInt64(&b.startRequests) == 0 {
		b.logger.Info("Starting bpf recorder")

		if err := b.StartRecording(); err != nil {
			return nil, fmt.Errorf("start recording: %w", err)
		}
	} else {
		b.logger.Info("bpf recorder already running")
	}

	atomic.AddInt64(&b.startRequests, 1)

	return &api.EmptyResponse{}, nil
}

func (b *BpfRecorder) Stop(
	context.Context, *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	b.startMu.Lock()
	defer b.startMu.Unlock()

	if atomic.LoadInt64(&b.startRequests) == 0 {
		b.logger.Info("bpf recorder not running")

		return &api.EmptyResponse{}, nil
	}

	atomic.AddInt64(&b.startRequests, -1)

	if atomic.LoadInt64(&b.startRequests) == 0 {
		b.logger.Info("Stopping bpf recorder")

		if err := b.StopRecording(); err != nil {
			return nil, fmt.Errorf("stop recording: %w", err)
		}
	} else {
		b.logger.Info("Not stopping because another recording is in progress")
	}

	return &api.EmptyResponse{}, nil
}

// SyscallsForProfile returns the syscall names for the provided profile name.
// The recorded data stays in place until ResetSyscallsForProfile is called, so
// that the caller can retry if persisting the profile fails.
func (b *BpfRecorder) SyscallsForProfile(
	_ context.Context, r *api.ProfileRequest,
) (*api.SyscallsResponse, error) {
	if atomic.LoadInt64(&b.startRequests) == 0 {
		return nil, errors.New("bpf recorder not running")
	}

	if b.Seccomp == nil {
		return nil, errors.New("not seccomp profiles recording running")
	}

	b.logger.Info("Getting syscalls for profile", "profile", r.GetName())

	keys, err := b.getKeysForProfileWithRetry(r.GetName())
	if err != nil {
		return nil, err
	}

	b.attachUnattachMutex.RLock()
	syscalls, err := b.Seccomp.Syscalls(b, keys)
	b.attachUnattachMutex.RUnlock()

	if err != nil {
		b.logger.Error(err, "Failed to get syscalls", "profile", r.GetName(), "keys", keys)

		return nil, err
	}

	b.logger.Info(
		fmt.Sprintf("Found %d syscalls for profile", len(syscalls)),
		"profile", r.GetName(),
		"keys", keys,
	)

	return &api.SyscallsResponse{
		Syscalls: syscalls,
		GoArch:   runtime.GOARCH,
	}, nil
}

// ResetSyscallsForProfile drops the syscalls recorded for the provided
// profile. It is called once the profile has been persisted.
func (b *BpfRecorder) ResetSyscallsForProfile(
	_ context.Context, r *api.ProfileRequest,
) (*api.EmptyResponse, error) {
	if b.Seccomp == nil {
		return nil, errors.New("not seccomp profiles recording running")
	}

	b.resetProfile(r.GetName(), func(keys []uint64) {
		b.Seccomp.Clear(b, keys)
	})

	return &api.EmptyResponse{}, nil
}

// ApparmorForProfile returns the AppArmor rules for the provided profile name.
// The recorded data stays in place until ResetApparmorForProfile is called, so
// that the caller can retry if persisting the profile fails.
func (b *BpfRecorder) ApparmorForProfile(
	_ context.Context, r *api.ProfileRequest,
) (*api.ApparmorResponse, error) {
	if atomic.LoadInt64(&b.startRequests) == 0 {
		return nil, errors.New("bpf recorder not running")
	}

	if b.AppArmor == nil {
		return nil, errors.New("no apparmor profiles recording running")
	}

	b.logger.Info("Getting apparmor profile", "profile", r.GetName())

	keys, err := b.getKeysForProfileWithRetry(r.GetName())
	if err != nil {
		return nil, err
	}

	b.attachUnattachMutex.RLock()
	apparmor, ok := b.AppArmor.GetAppArmorProcessed(keys)
	b.attachUnattachMutex.RUnlock()

	if !ok {
		// Never hand out an empty profile: it would replace the one stored
		// for this recording with one that allows nothing.
		b.logger.Info("No apparmor data recorded for profile", "profile", r.GetName(), "keys", keys)

		return nil, ErrNotFound
	}

	return &api.ApparmorResponse{
		Files: &api.ApparmorResponse_Files{
			AllowedExecutables: apparmor.FileProcessed.AllowedExecutables,
			AllowedLibraries:   apparmor.FileProcessed.AllowedLibraries,
			ReadonlyPaths:      apparmor.FileProcessed.ReadOnlyPaths,
			WriteonlyPaths:     apparmor.FileProcessed.WriteOnlyPaths,
			ReadwritePaths:     apparmor.FileProcessed.ReadWritePaths,
		},
		Capabilities: apparmor.Capabilities,
		Socket: &api.ApparmorResponse_Socket{
			UseRaw: apparmor.Socket.UseRaw,
			UseTcp: apparmor.Socket.UseTCP,
			UseUdp: apparmor.Socket.UseUDP,
		},
	}, nil
}

// ResetApparmorForProfile drops the AppArmor data recorded for the provided
// profile. It is called once the profile has been persisted.
func (b *BpfRecorder) ResetApparmorForProfile(
	_ context.Context, r *api.ProfileRequest,
) (*api.EmptyResponse, error) {
	if b.AppArmor == nil {
		return nil, errors.New("no apparmor profiles recording running")
	}

	b.resetProfile(r.GetName(), b.AppArmor.Clear)

	return &api.EmptyResponse{}, nil
}

// resetProfile drops the data of a collected profile with clearData. The keys
// of its containers are only forgotten once no other profile of them is left
// to collect, as a container can be recorded for seccomp and AppArmor at the
// same time.
func (b *BpfRecorder) resetProfile(profile string, clearData func([]uint64)) {
	containerIDs := b.containerIDToProfileMap.Containers(profile)
	if len(containerIDs) == 0 {
		return
	}

	b.attachUnattachMutex.RLock()
	b.containerKeys.WithKeysOf(containerIDs, func(keys []uint64) {
		b.logger.Info("Resetting recorded data for profile",
			"profile", profile, "containerIDs", containerIDs, "keys", keys)

		clearData(keys)
	})
	b.attachUnattachMutex.RUnlock()

	b.collectedProfiles.Store(profile, struct{}{})

	for _, containerID := range b.containerIDToProfileMap.DeleteProfile(profile) {
		b.containerKeys.DeleteContainer(containerID)
	}
}

func (b *BpfRecorder) getKeysForProfileWithRetry(profile string) ([]uint64, error) {
	if _, collected := b.collectedProfiles.Load(profile); collected {
		b.logger.Info("Profile was already collected", "profile", profile)

		return nil, ErrNotFound
	}

	// There is a chance to miss the PID if concurrent processes are being
	// analyzed. If we request the `SyscallsForProfile` exactly between two
	// events, while the first one is from a different recording container and
	// we have to expect the profile in the second event. We try to overcome
	// this race by retrying, but with a more loose backoff strategy than
	// retrying to retrieve the in-cluster container ID.
	var (
		keys []uint64
		try  = -1
	)

	if err := util.Retry(
		func() error {
			try++
			b.logger.Info("Looking up recording keys for profile", "profile", profile, "try", try)

			if found := b.getKeysForProfile(profile); len(found) > 0 {
				keys = found
				b.logger.Info("Found recording keys for profile", "profile", profile, "keys", keys)

				return nil
			}

			b.logger.Info("No recording keys found for profile", "profile", profile)

			return ErrNotFound
		},
		func(error) bool { return true },
	); err != nil {
		return nil, ErrNotFound
	}

	return keys, nil
}

func (b *BpfRecorder) getKeysForProfile(profile string) []uint64 {
	containerIDs := b.containerIDToProfileMap.Containers(profile)
	if len(containerIDs) == 0 {
		return nil
	}

	b.logger.Info(
		"Found container ids for profile",
		"containerIDs",
		containerIDs,
		"profile",
		profile,
	)

	return b.containerKeys.KeysOf(containerIDs)
}

// Load loads the BPF code, does relocations, and gets references to the programs we want to attach.
// We try to front load as much work as possible so that starting a recording is quick.
// Recorder start races with container initialization, so we can't spend too much time then.
//
// Unloading is currently done implicitly on process exit.
func (b *BpfRecorder) Load() (err error) {
	var module *bpf.Module

	b.logger.Info("Loading bpf module...")

	if err := b.findBtfPath(); err != nil {
		return fmt.Errorf("find btf: %w", err)
	}

	bpfObject, err := bpfObjectForArch(runtime.GOARCH)
	if err != nil {
		return err
	}

	module, err = b.NewModuleFromBufferArgs(&bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
		BTFObjPath: b.btfPath,
	})
	if err != nil {
		return fmt.Errorf("load bpf module: %w", err)
	}

	b.module = module

	if b.programName != "" {
		programName := []byte(filepath.Base(b.programName))
		if len(programName) >= maxCommLen {
			programName = programName[:maxCommLen-1]
			b.logger.Info("Set truncated program name filter", "programName", string(programName))
		} else {
			b.logger.Info("Set program name filter", "programName", string(programName))
		}

		programName = append(programName, 0)
		if err := b.InitGlobalVariable(
			module, globalFilterName, programName,
		); err != nil {
			return fmt.Errorf("init global variable: %w", err)
		}
	}

	// In-cluster, record per cgroup where the host supports it, and per
	// mount namespace sequence number otherwise. Mount namespace inode
	// numbers are reused as soon as a container exits, so a container started
	// before a finished one got collected would add its data to the same key.
	// spoc records processes on the host, which share their cgroup with
	// unrelated processes, and matches the recorded data with the mount
	// namespace inode it finds in /proc, so it stays with those.
	switch {
	case b.clientset == nil:
		b.logger.Info("Recording per mount namespace")
	case b.IsCgroupV2():
		if err := b.InitGlobalVariable(module, globalUseCgroupID, true); err != nil {
			return fmt.Errorf("init global variable: %w", err)
		}

		b.uniqueKeys = true
		b.logger.Info("Recording per cgroup")
	default:
		if err := b.InitGlobalVariable(module, globalUseMntnsSeq, true); err != nil {
			return fmt.Errorf("init global variable: %w", err)
		}

		b.uniqueKeys = true
		b.logger.Info("Recording per mount namespace sequence number")
	}

	b.logger.Info("Loading bpf object from module")

	if err := b.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	if b.excludeMountNamespace != 0 {
		excludeMntns, err := b.GetMap(module, mapExcludeMntns)
		if err != nil {
			return fmt.Errorf("getting exclude_mntns map failed: %w", err)
		}

		if err := b.UpdateValue(
			excludeMntns,
			b.excludeMountNamespace,
			[]byte{excludeMntnsEnabled},
		); err != nil {
			return fmt.Errorf("updating exclude_mntns map failed: %w", err)
		}

		b.logger.Info("Excluding mount namespace", "mntns", b.excludeMountNamespace)
	}

	if err := b.loadPrograms(baseHooks); err != nil {
		return fmt.Errorf("loading base hooks: %w", err)
	}

	if b.AppArmor != nil {
		if err := b.AppArmor.Load(b); err != nil {
			// Only log an error here, if Apparmor cannot be loaded. This is because it is
			// enabled by default, and there are Linux distributions which either do not
			// support Apparmor or BPF LSM is not yet available.
			//
			// see also https://github.com/kubernetes-sigs/security-profiles-operator/issues/2384
			b.logger.Error(err, "load AppArmor bpf hooks")
		}
	}

	if b.Seccomp != nil {
		if err := b.Seccomp.Load(b); err != nil {
			return fmt.Errorf("loading seccomp bpf hooks: %w", err)
		}
	}

	b.isRecordingBpfMap, err = b.GetMap(b.module, mapIsRecording)
	if err != nil {
		return fmt.Errorf("getting `is_recording` map: %w", err)
	}

	for name, bpfMap := range map[string]**bpf.BPFMap{
		mapActivePids:          &b.activePidsBpfMap,
		mapChildPids:           &b.childPidsBpfMap,
		mapExcludeKeys:         &b.excludeKeysBpfMap,
		mapSeccompInitialized:  &b.seccompInitBpfMap,
		mapApparmorInitialized: &b.apparmorInitBpfMap,
		mapLostEvents:          &b.lostEventsBpfMap,
	} {
		if *bpfMap, err = b.GetMap(b.module, name); err != nil {
			return fmt.Errorf("getting `%s` map: %w", name, err)
		}
	}

	const timeout = 300

	events := make(chan []byte)

	ringbuf, err := b.InitRingBuf(
		b.module,
		mapEvents,
		events,
	)
	if err != nil {
		return fmt.Errorf("init events ringbuffer: %w", err)
	}

	b.PollRingBuffer(ringbuf, timeout)

	go b.processEvents(events)
	go b.reportLostEvents()

	b.logger.Info("BPF module successfully loaded.")

	return nil
}

// reportLostEvents periodically logs the data the BPF program had to drop.
// Such drops make the recorded profiles incomplete, so they must not go
// unnoticed.
func (b *BpfRecorder) reportLostEvents() {
	ticker := time.NewTicker(lostEventsInterval)
	defer ticker.Stop()

	for range ticker.C {
		b.checkLostEvents()
	}
}

func (b *BpfRecorder) checkLostEvents() {
	if b.lostEventsBpfMap == nil {
		return
	}

	b.lostEventsMu.Lock()
	defer b.lostEventsMu.Unlock()

	for reason := range lostReasons {
		value, err := b.GetValue(b.lostEventsBpfMap, reason)
		if err != nil {
			b.logger.Error(err, "Unable to read lost events counter", "reason", reason)

			continue
		}

		total := sumPerCPU(value)

		lost := total - b.lostEvents[reason]
		if total < b.lostEvents[reason] || lost == 0 {
			b.lostEvents[reason] = total

			continue
		}

		b.lostEvents[reason] = total

		switch reason {
		case lostRingbuf:
			b.logger.Info(
				"WARNING: the BPF ring buffer was full, recorded profiles may be incomplete",
				"lostEvents", lost, "lostEventsTotal", total,
			)
		case lostFileEventBusy:
			b.logger.Info(
				"WARNING: file events were dropped by concurrent hooks, "+
					"recorded AppArmor profiles may be incomplete",
				"lostFileEvents", lost, "lostFileEventsTotal", total,
			)
		case lostSyscallsMapFull:
			b.logger.Info(
				"WARNING: too many workloads are recorded at once, "+
					"recorded seccomp profiles may be incomplete",
				"lostSyscalls", lost, "lostSyscallsTotal", total,
			)
		}
	}
}

// sumPerCPU sums the u64 values of a per CPU map element.
func sumPerCPU(value []byte) uint64 {
	var sum uint64

	for i := 0; i+8 <= len(value); i += 8 {
		sum += binary.LittleEndian.Uint64(value[i : i+8])
	}

	return sum
}

// bpfObjectForArch returns the compiled BPF program for the architecture.
func bpfObjectForArch(arch string) ([]byte, error) {
	switch arch {
	case "amd64":
		return bpfAmd64, nil
	case "arm64":
		return bpfArm64, nil
	default:
		return nil, fmt.Errorf("architecture %s is currently unsupported", arch)
	}
}

func (b *BpfRecorder) loadPrograms(programNames []string) error {
	for _, name := range programNames {
		prog, err := b.GetProgram(b.module, name)
		if err != nil {
			return fmt.Errorf("get bpf program %s: %w", name, err)
		}

		_, err = b.AttachGeneric(prog)
		if err != nil {
			return fmt.Errorf("attach bpf program %s: %w", name, err)
		}

		b.logger.Info("attached bpf program", "name", name)
	}

	return nil
}

func (b *BpfRecorder) StartRecording() (err error) {
	b.attachUnattachMutex.Lock()
	defer b.attachUnattachMutex.Unlock()

	b.logger.Info("Start BPF recording...")

	if b.module == nil {
		return ErrStartBeforeLoad
	}

	// Start with fresh process tracking, the maps are not maintained while
	// nothing is recording.
	if err := b.clearPidMaps(); err != nil {
		return err
	}

	if err := b.UpdateValue(b.isRecordingBpfMap, 0, []byte{1}); err != nil {
		return fmt.Errorf("failed to update `is_recording`: %w", err)
	}

	syscall.Getgid() // Notify BPF program that is_recording has changed.

	if b.AppArmor != nil {
		if err := b.AppArmor.StartRecording(b); err != nil {
			// Only log an error here, if Apparmor cannot be loaded. This is because it is
			// enabled by default, and there are Linux distributions which either do not
			// support Apparmor or BPF LSM is not yet available.
			//
			// see also https://github.com/kubernetes-sigs/security-profiles-operator/issues/2384
			b.logger.Error(err, "attach AppArmor bpf hooks")
		}
	}

	if b.Seccomp != nil {
		if err := b.Seccomp.StartRecording(b); err != nil {
			return fmt.Errorf("starting seccomp recording: %w", err)
		}
	}

	b.logger.Info("Recording started.")

	return nil
}

func (b *BpfRecorder) StopRecording() error {
	b.attachUnattachMutex.Lock()
	defer b.attachUnattachMutex.Unlock()

	b.logger.Info("Stop BPF recording: Detaching all programs...")

	if err := b.UpdateValue(b.isRecordingBpfMap, 0, []byte{0}); err != nil {
		return fmt.Errorf("failed to update `is_recording`: %w", err)
	}

	syscall.Getgid() // Notify BPF program that is_recording has changed.

	if b.Seccomp != nil {
		if err := b.Seccomp.StopRecording(b); err != nil {
			return fmt.Errorf("stopping seccomp recording: %w", err)
		}
	}

	if b.AppArmor != nil {
		if err := b.AppArmor.StopRecording(b); err != nil {
			return fmt.Errorf("stopping apparmor recording: %w", err)
		}
	}

	if err := b.clearPidMaps(); err != nil {
		return err
	}

	b.checkLostEvents()

	// Nothing is recording any more, so the per-session lookup tables can be
	// released. Profiles are always collected before the recording is stopped.
	// Ending the generation first makes handlers which are still in flight skip
	// their writes. A handler which already passed that check can still land an
	// entry here, which is why it re-checks afterwards and removes its own.
	b.recordingGeneration.Add(1)
	b.containerKeys.Clear()
	b.containerIDToProfileMap.Clear()
	b.collectedProfiles.Clear()
	b.recentExits.DeleteAll()
	// The negative cache is per session as well. A pod update can add recording
	// annotations to a container that is already running, so an entry taken in
	// one session must not suppress the lookup in the next one for the rest of
	// its hour-long TTL.
	b.containersWithoutProfile.DeleteAll()

	b.logger.Info("Recording stopped.")

	return nil
}

// clearPidMaps empties the per session tracking maps. A PID which exited while
// nothing was recording stays in them otherwise, so a new process reusing that
// PID would never be reported.
func (b *BpfRecorder) clearPidMaps() error {
	for _, bpfMap := range []*bpf.BPFMap{
		b.activePidsBpfMap, b.childPidsBpfMap, b.excludeKeysBpfMap,
		b.seccompInitBpfMap, b.apparmorInitBpfMap,
	} {
		if err := clearBpfMap(b, bpfMap); err != nil {
			return fmt.Errorf("clear process tracking map: %w", err)
		}
	}

	return nil
}

// clearBpfMap deletes all keys of bpfMap. The keys are collected first, as
// deleting while iterating makes the iteration start over.
func clearBpfMap(b *BpfRecorder, bpfMap *bpf.BPFMap) error {
	if bpfMap == nil {
		return nil
	}

	var keys [][]byte

	it := b.BPFMapIterator(bpfMap)
	for b.BPFMapIteratorNext(it) {
		keys = append(keys, bytes.Clone(it.Key()))
	}

	for _, key := range keys {
		if err := bpfMap.DeleteKey(unsafe.Pointer(&key[0])); err != nil &&
			!errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("delete key: %w", err)
		}
	}

	return nil
}

func (b *BpfRecorder) findBtfPath() error {
	const btf = "/sys/kernel/btf/vmlinux"

	// Use the system btf if possible
	if _, err := b.Stat(btf); err == nil {
		b.logger.Info("Using system btf file")

		return nil
	}

	return fmt.Errorf(
		"we dropped support for in-memory btf, please use a kernel which supports %s",
		btf,
	)
}

func (b *BpfRecorder) processEvents(events chan []byte) {
	b.logger.Info("Processing bpf events")
	defer b.logger.Info("Stopped processing bpf events")

	for event := range events {
		b.handleEvent(event)
	}
}

func (b *BpfRecorder) handleEvent(eventBytes []byte) {
	var event bpfEvent

	if !event.unmarshal(eventBytes) {
		b.logger.Error(
			errShortEvent, "Couldn't read event structure",
			"got", len(eventBytes), "want", bpfEventSize,
		)

		return
	}

	switch event.Type {
	case uint8(eventTypeNewPid):
		b.scheduleNewPidEvent(event.Pid, event.Mntns, event.Key)
	case uint8(eventTypeExit):
		b.handleExitEvent(&event)
	case uint8(eventTypeAppArmorFile):
		if b.AppArmor != nil {
			b.AppArmor.handleFileEvent(&event)
		}
	case uint8(eventTypeAppArmorSocket):
		if b.AppArmor != nil {
			b.AppArmor.handleSocketEvent(&event)
		}
	case uint8(eventTypeAppArmorCap):
		if b.AppArmor != nil {
			b.AppArmor.handleCapabilityEvent(&event)
		}
	case uint8(eventTypeClearMntns):
		if b.AppArmor != nil {
			b.AppArmor.clearKey(&event)
		}
	}
}

// scheduleNewPidEvent queues a new pid event for the handler pool.
//
// It never blocks: handleNewPidEvent does a cgroup lookup and can hit the
// Kubernetes API, and the caller is the single event processing loop which also
// delivers the AppArmor events over an unbuffered channel. Stalling it makes the
// kernel drop recorded events, so a saturated queue drops the event instead.
func (b *BpfRecorder) scheduleNewPidEvent(pid, mntns uint32, key uint64) {
	// The handlers live for the lifetime of the recorder. There is no teardown
	// because both the daemon and spoc keep a recorder until the process exits,
	// and a shutdown path would have to guard every send against a closed
	// channel for no practical gain.
	b.startPidHandlers.Do(func() {
		for range maxNewPidHandlers {
			go b.runPidHandler()
		}
	})

	event := newPidEvent{
		pid:        pid,
		mntns:      mntns,
		key:        key,
		generation: b.recordingGeneration.Load(),
	}

	select {
	case b.newPidEvents <- event:
	default:
		b.logger.Info(
			"Dropping new pid event because the handler queue is full",
			"pid", pid, "mntns", mntns, "queueSize", newPidQueueSize,
		)
	}
}

func (b *BpfRecorder) runPidHandler() {
	for event := range b.newPidEvents {
		b.handleNewPidEvent(event.pid, event.mntns, event.key, event.generation)
	}
}

func (b *BpfRecorder) handleNewPidEvent(pid, mntns uint32, key, generation uint64) {
	b.logger.V(config.VerboseLevel).Info("Received new pid", "pid", pid, "mntns", mntns, "key", key)

	if b.clientset == nil {
		// spoc: we're running outside of a kubernetes context.
		return
	}

	// Look up the container ID based on PID from cgroup file. The cache is
	// keyed by PID and process start time, so a process reusing a PID gets
	// its own entry.
	containerID, err := b.ContainerIDForPID(b.pidToContainerIDCache, int(pid))
	if err != nil {
		b.logger.V(config.VerboseLevel).Info(
			"No container ID found for PID",
			"pid", pid, "mntns", mntns, "error", err.Error(),
		)

		// The process runs outside of any container.
		if errors.Is(err, util.ErrContainerIDNotFound) {
			b.excludeKey(key, generation)
		}

		return
	}

	if b.recordingGeneration.Load() != generation {
		b.logger.V(config.VerboseLevel).Info(
			"Discarding new pid event from a finished recording",
			"pid", pid, "mntns", mntns, "containerID", containerID,
		)

		return
	}

	b.containerKeys.Insert(key, containerID)

	b.logger.V(config.VerboseLevel).Info(
		"Found container ID for PID", "pid", pid,
		"mntns", mntns, "key", key, "containerID", containerID,
	)

	profile, err := b.findProfileForContainerID(containerID)
	if err != nil {
		if errors.Is(err, errNoProfileForContainer) {
			// The container exists and is not recorded, its data would
			// only fill up the maps.
			b.containerKeys.Delete(key)
			b.excludeKey(key, generation)

			return
		}

		b.logger.Error(err, "Unable to find profile in cluster for container ID",
			"id", containerID, "pid", pid, "mntns", mntns)

		return
	}

	b.logger.Info(
		"Found profile in cluster for container ID", "containerID", containerID,
		"pid", pid, "mntns", mntns, "profile", profile,
	)

	b.trackProfileMetric(mntns, profile)

	// The generation may have ended while the lookups above were running, in
	// which case StopRecording has already cleared the tables and these entries
	// would linger into the next recording.
	if b.recordingGeneration.Load() != generation {
		b.containerKeys.Delete(key)
		b.containerIDToProfileMap.Delete(containerID)
	}
}

// excludeKey stops recording a workload which is not recorded, and drops what
// got recorded for it so far. This is only done with keys which are never
// reused: an excluded mount namespace inode number could belong to a recorded
// container later on.
func (b *BpfRecorder) excludeKey(key, generation uint64) {
	if !b.uniqueKeys {
		return
	}

	b.attachUnattachMutex.RLock()
	defer b.attachUnattachMutex.RUnlock()

	// StopRecording holds the write lock while it ends the session and clears
	// the maps, so the session cannot end in between.
	if b.recordingGeneration.Load() != generation {
		return
	}

	b.logger.V(config.VerboseLevel).Info("Excluding workload from recording", "key", key)

	if b.excludeKeysBpfMap != nil {
		if err := b.UpdateValue64(
			b.excludeKeysBpfMap,
			key,
			[]byte{excludeMntnsEnabled},
		); err != nil {
			b.logger.Error(err, "Unable to exclude workload from recording", "key", key)
		}
	}

	if b.Seccomp != nil {
		b.Seccomp.Clear(b, []uint64{key})
	}

	if b.AppArmor != nil {
		b.AppArmor.Exclude(key)
	}
}

func (b *BpfRecorder) handleExitEvent(exitEvent *bpfEvent) {
	// Logged at the default level, unlike the other per-process events: an exit
	// only reaches userspace for a pid the recorder actually tracks, and spoc
	// --no-proc-start has no other way to tell that the recording caught up with
	// an externally started process before it is stopped.
	b.logger.Info("Record pid exit", "pid", exitEvent.Pid)

	// Remember the exit first, so that a WaitForPidExit which registers right
	// after this still observes it.
	b.recentExits.Set(exitEvent.Pid, struct{}{}, ttlcache.DefaultTTL)

	// LoadAndDelete hands the channel to exactly one caller, so a repeated exit
	// event for the same pid cannot close it twice. Closing rather than sending
	// wakes every waiter sharing the channel.
	if waiter, ok := b.exitWaiters.LoadAndDelete(exitEvent.Pid); ok {
		if done, ok := waiter.(chan struct{}); ok {
			close(done)
		}
	}
}

// FindProcMountNamespace is looking up the mnt ns for a given PID.
func (b *BpfRecorder) FindProcMountNamespace(pid uint32) (uint32, error) {
	// This requires the container to run with host PID, otherwise we will get
	// the namespace from the container.
	procLink := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	res, err := b.Readlink(procLink)
	if err != nil {
		return 0, fmt.Errorf("read mount namespace link: %w", err)
	}

	stripped := strings.TrimPrefix(res, "mnt:[")
	stripped = strings.TrimSuffix(stripped, "]")

	ns, err := strconv.ParseUint(stripped, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("convert namespace to integer: %w", err)
	}

	return uint32(ns), nil
}

func (b *BpfRecorder) trackProfileMetric(mntns uint32, profile string) {
	if b.metrics == nil {
		return
	}

	b.metrics.Send(&apimetrics.BpfRequest{
		Node:           b.nodeName,
		Profile:        profile,
		MountNamespace: mntns,
	})
}

var errNoProfileForContainer = errors.New("container has no recording annotation")

func (b *BpfRecorder) findProfileForContainerID(id string) (string, error) {
	if b.containersWithoutProfile.Get(id) != nil {
		// Returned once per BPF event from an unannotated container, so no
		// wrapping: the caller logs the container ID separately.
		return "", errNoProfileForContainer
	}

	if profile, ok := b.containerIDToProfileMap.Get(id); ok {
		b.logger.V(config.VerboseLevel).Info(
			"Found profile in cache", "containerID", id, "profile", profile,
		)

		return profile, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	const (
		backoffDuration = 100 * time.Millisecond
		backoffFactor   = 1.2
		backoffSteps    = 20
	)

	try := -1

	if err := util.RetryEx(
		&wait.Backoff{
			Duration: backoffDuration,
			Factor:   backoffFactor,
			Steps:    backoffSteps,
		},
		func() error {
			try++
			b.logger.V(config.VerboseLevel).
				Info("Looking up container ID in cluster", "id", id, "try", try)

			pods, err := b.ListPods(ctx, b.clientset, b.nodeName)
			if err != nil {
				return fmt.Errorf("list node pods: %w", err)
			}

			if pods == nil {
				return errors.New("no pods found in cluster")
			}

			for p := range pods.Items {
				pod := &pods.Items[p]

				statuses := slices.Concat(
					pod.Status.InitContainerStatuses,
					pod.Status.ContainerStatuses)
				for c := range statuses {
					containerStatus := statuses[c]
					fullContainerID := containerStatus.ContainerID
					containerName := containerStatus.Name

					// The container ID is not yet available in the container status of the pod.
					// This container can be skipped for now, the status will be checked again later.
					if fullContainerID == "" {
						b.logger.Info(
							"Container ID not yet available in cluster",
							"containerID", id,
							"podName", pod.Name,
							"containerName", containerName,
						)

						continue
					}

					containerID := util.ContainerIDRegex.FindString(fullContainerID)
					if containerID == "" {
						b.logger.Error(err,
							"Unable to parse container ID from container status available in pod",
							"fullContainerID", fullContainerID,
							"podName", pod.Name,
							"containerName", containerName,
						)

						continue
					}

					b.logger.V(config.VerboseLevel).Info(
						"Found Container ID in cluster",
						"containerID", containerID,
						"podName", pod.Name,
						"containerName", containerName,
					)

					for _, annotation := range []string{
						config.SeccompProfileRecordBpfAnnotationKey,
						config.ApparmorProfileRecordBpfAnnotationKey,
					} {
						key := annotation + containerName

						profile, ok := pod.Annotations[key]
						if ok && profile != "" {
							b.logger.Info(
								"Cache this profile found in cluster",
								"profile", profile,
								"containerID", containerID,
								"podName", pod.Name,
								"containerName", containerName,
							)
							b.containerIDToProfileMap.Insert(containerID, profile)
						}
					}

					// Stop looking for this container ID regadless of a profile was found or not.
					if containerID == id {
						return nil
					}
				}
			}

			return fmt.Errorf("container ID not found in cluster: %s", id)
		},
		func(error) bool { return true },
	); err != nil {
		return "", fmt.Errorf("searching container ID %s: %w", id, err)
	}

	if profile, ok := b.containerIDToProfileMap.Get(id); ok {
		b.logger.Info(
			"Found profile in cluster for container ID",
			"profile", profile,
			"containerID", id,
		)

		return profile, nil
	}

	// The container exists but is not being recorded. Remember that, so the
	// next event from it does not list every pod on the node again.
	b.containersWithoutProfile.Set(id, struct{}{}, ttlcache.DefaultTTL)

	return "", errNoProfileForContainer
}

// WaitForPidExit waits for a specific PID to exit.
// When running outside of Kubernetes as spoc, we have the use case of
// waiting for a specific PID to exit.
func (b *BpfRecorder) WaitForPidExit(ctx context.Context, pid uint32) error {
	// Concurrent waiters for the same pid share one channel, so that closing it
	// wakes all of them. Registering happens before the recorded exits are
	// consulted, so an exit landing between the two cannot be missed.
	waiter, _ := b.exitWaiters.LoadOrStore(pid, make(chan struct{}))

	done, ok := waiter.(chan struct{})
	if !ok {
		return fmt.Errorf("unexpected exit waiter type: %T", waiter)
	}

	// Only drop the registration if it is still ours, so giving up does not
	// deregister a channel another waiter is parked on.
	defer b.exitWaiters.CompareAndDelete(pid, done)

	if b.recentExits.Get(pid) != nil {
		return nil
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("waiting for pid exit: %w", ctx.Err())
	}
}

var bpfLSMRegex = regexp.MustCompile(`(^|,)bpf(,|$)`)

func BPFLSMEnabled() bool {
	contents, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}

	return bpfLSMRegex.Match(contents)
}
