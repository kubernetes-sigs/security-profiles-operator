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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/blang/semver/v4"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/bimap"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	defaultTimeout          time.Duration = time.Minute
	maxMsgSize              int           = 16 * 1024 * 1024
	maxCommLen              int           = 64
	defaultCacheTimeout     time.Duration = time.Hour
	maxCacheItems           uint64        = 1000
	defaultHostPid          uint32        = 1
	defaultByteNum          int           = 4
	recordingSeccomp        int           = 1
	recordingAppArmor       int           = 2
	pathMax                 int           = 4096
	eventTypeNewPid         int           = 0
	eventTypeExit           int           = 1
	eventTypeAppArmorFile   int           = 2
	eventTypeAppArmorSocket int           = 3
	eventTypeAppArmorCap    int           = 4
	eventTypeClearMntns     int           = 5
	excludeMntnsEnabled     byte          = 1
)

// BpfRecorder is the main structure of this package.
type BpfRecorder struct {
	api.UnimplementedBpfRecorderServer
	impl
	logger                  logr.Logger
	startRequests           int64
	btfPath                 string
	pidToContainerIDCache   *ttlcache.Cache[string, string]
	mntnsToContainerIDMap   *bimap.BiMap[uint32, string]
	containerIDToProfileMap *bimap.BiMap[string, string]
	nodeName                string
	clientset               *kubernetes.Clientset
	excludeMountNamespace   uint32
	attachUnattachMutex     sync.RWMutex
	metricsClient           apimetrics.Metrics_BpfIncClient
	programName             string
	module                  *bpf.Module
	isRecordingBpfMap       *bpf.BPFMap

	AppArmor *AppArmorRecorder
	Seccomp  *SeccompRecorder

	recordedExits sync.Map
}

// We use a single shared event ringbuf for all userspace communication.
// This ensures that all previous events have already been processed.
type bpfEvent struct {
	Pid   uint32
	Mntns uint32
	Type  uint8
	Flags uint64
	Data  [pathMax]uint8
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
		mntnsToContainerIDMap:   bimap.New[uint32, string](),
		containerIDToProfileMap: bimap.New[string, string](),
		attachUnattachMutex:     sync.RWMutex{},
		programName:             programName,
		AppArmor:                appArmor,
		Seccomp:                 seccomp,
		recordedExits:           sync.Map{},
	}
}

// Syscalls returns the bpf map containing the PID (key) to syscalls (value)
// data.
func (b *BpfRecorder) Syscalls() *bpf.BPFMap {
	return b.Seccomp.syscalls
}

// Run the BpfRecorder.
func (b *BpfRecorder) Run() error {
	b.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))

	for _, cache := range []*ttlcache.Cache[string, string]{
		b.pidToContainerIDCache,
	} {
		go cache.Start()
	}

	b.nodeName = b.Getenv(config.NodeNameEnvKey)
	if b.nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		b.logger.Error(err, "unable to run recorder")

		return err
	}

	b.logger.Info("Starting ebpf recorder on node: " + b.nodeName)

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

	conn, cancel, err := b.connectMetrics()
	if err != nil {
		return fmt.Errorf("connect to metrics server: %w", err)
	}

	if cancel != nil {
		defer cancel()
	}

	if conn != nil {
		defer func() {
			if err := b.CloseGRPC(conn); err != nil {
				b.logger.Error(err, "unable to close GRPC connection")
			}
		}()
	}

	b.excludeMountNamespace, err = b.FindProcMountNamespace(defaultHostPid)
	if err != nil {
		return fmt.Errorf("retrieve current mount namespace: %w", err)
	}

	b.logger.Info("Got system mount namespace: " + strconv.FormatUint(uint64(b.excludeMountNamespace), 10))

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

func (b *BpfRecorder) connectMetrics() (conn *grpc.ClientConn, cancel context.CancelFunc, err error) {
	if err := util.Retry(func() (err error) {
		conn, cancel, err = b.DialMetrics()
		if err != nil {
			return fmt.Errorf("connecting to local metrics GRPC server: %w", err)
		}
		client := apimetrics.NewMetricsClient(conn)

		b.metricsClient, err = b.BpfIncClient(client)
		if err != nil {
			cancel()
			if err := b.CloseGRPC(conn); err != nil {
				b.logger.Error(err, "Unable to close GRPC connection")
			}

			return fmt.Errorf("create metrics bpf client: %w", err)
		}

		return nil
	}, func(err error) bool { return true }); err != nil {
		return nil, nil, fmt.Errorf("connect to local GRPC server: %w", err)
	}

	return conn, cancel, nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	//nolint:staticcheck // we'll use this API once we have an appropriate alternative
	conn, err := grpc.DialContext(
		ctx,
		"unix://"+config.GRPCServerSocketBpfRecorder,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()

		return nil, nil, fmt.Errorf("GRPC dial: %w", err)
	}

	return conn, cancel, nil
}

func (b *BpfRecorder) Start(
	context.Context, *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	if b.startRequests == 0 {
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
	if b.startRequests == 0 {
		b.logger.Info("bpf recorder not running")

		return &api.EmptyResponse{}, nil
	}

	atomic.AddInt64(&b.startRequests, -1)

	if b.startRequests == 0 {
		b.logger.Info("Stopping bpf recorder")

		if err := b.StopRecording(); err != nil {
			return nil, fmt.Errorf("start recording: %w", err)
		}
	} else {
		b.logger.Info("Not stopping because another recording is in progress")
	}

	return &api.EmptyResponse{}, nil
}

// SyscallsForProfile returns the syscall names for the provided profile name.
func (b *BpfRecorder) SyscallsForProfile(
	_ context.Context, r *api.ProfileRequest,
) (*api.SyscallsResponse, error) {
	if b.startRequests == 0 {
		return nil, errors.New("bpf recorder not running")
	}

	if b.Seccomp == nil {
		return nil, errors.New("not seccomp profiles recording running")
	}

	b.logger.Info("Getting syscalls for profile " + r.GetName())

	mntns, err := b.getMntnsForProfileWithRetry(r.GetName())
	if err != nil {
		return nil, err
	}

	b.attachUnattachMutex.RLock()
	syscalls, err := b.Seccomp.PopSyscalls(b, mntns)
	b.attachUnattachMutex.RUnlock()

	if err != nil {
		b.logger.Error(err, "Failed to get syscalls for mntns", "mntns", mntns)

		return nil, err
	}

	b.logger.Info(
		fmt.Sprintf("Found %d syscalls for profile", len(syscalls)),
		"profile", r.GetName(),
		"mntns", mntns,
	)

	return &api.SyscallsResponse{
		Syscalls: syscalls,
		GoArch:   runtime.GOARCH,
	}, nil
}

func (b *BpfRecorder) ApparmorForProfile(
	_ context.Context, r *api.ProfileRequest,
) (*api.ApparmorResponse, error) {
	if b.startRequests == 0 {
		return nil, errors.New("bpf recorder not running")
	}

	if b.AppArmor == nil {
		return nil, errors.New("no apparmor profiles recording running")
	}

	b.logger.Info("Getting apparmor profile for profile " + r.GetName())

	mntns, err := b.getMntnsForProfileWithRetry(r.GetName())
	if err != nil {
		return nil, err
	}

	b.attachUnattachMutex.RLock()
	apparmor := b.AppArmor.GetAppArmorProcessed(mntns)
	b.attachUnattachMutex.RUnlock()

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

func (b *BpfRecorder) getMntnsForProfileWithRetry(profile string) (uint32, error) {
	// There is a chance to miss the PID if concurrent processes are being
	// analyzed. If we request the `SyscallsForProfile` exactly between two
	// events, while the first one is from a different recording container and
	// we have to expect the profile in the second event. We try to overcome
	// this race by retrying, but with a more loose backoff strategy than
	// retrying to retrieve the in-cluster container ID.
	var (
		mntns uint32
		try   = -1
	)

	if err := util.Retry(
		func() error {
			try++
			b.logger.Info("Looking up mount namespace for profile", "profile", profile, "try", try)
			if foundMntns, ok := b.getMntnsForProfile(profile); ok {
				mntns = foundMntns
				b.logger.Info("Found mount namespace for profile", "profile", profile, "mntns", mntns)

				return nil
			}
			b.logger.Info("No mount namespace found for profile", "profile", profile)

			return ErrNotFound
		},
		func(error) bool { return true },
	); err != nil {
		return mntns, ErrNotFound
	}

	return mntns, nil
}

func (b *BpfRecorder) getMntnsForProfile(profile string) (uint32, bool) {
	if containerID, ok := b.containerIDToProfileMap.GetBackwards(profile); ok {
		b.logger.Info("Found container id for profile", "containerID", containerID, "profile", profile)

		if mntns, ok := b.mntnsToContainerIDMap.GetBackwards(containerID); ok {
			return mntns, true
		}
	}

	return 0, false
}

var baseHooks = []string{
	"sys_enter",
	"sys_exit_clone",
	"sys_enter_execve",
	"sys_enter_getgid",
	"sys_enter_prctl",
	"sched_process_exec",
	"sched_process_exit",
}

// Load loads the BPF code, does relocations, and gets references to the programs we want to attach.
// We try to front load as much work as possible so that starting a recording is quick.
// Recorder start races with container initialization, so we can't spend too much time then.
//
// Unloading is currently done implicitly on process exit.
func (b *BpfRecorder) Load() (err error) {
	var module *bpf.Module

	b.logger.Info("Loading bpf module...")

	b.btfPath, err = b.findBtfPath()
	if err != nil {
		return fmt.Errorf("find btf: %w", err)
	}

	var bpfObject []byte

	switch b.GoArch() {
	case "amd64":
		bpfObject = bpfAmd64
	case "arm64":
		bpfObject = bpfArm64
	default:
		return fmt.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
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
			b.logger.Info(fmt.Sprintf("Set truncated program name filter: '%s'", programName))
		} else {
			b.logger.Info(fmt.Sprintf("Set program name filter: '%s'", programName))
		}

		programName = append(programName, 0)
		if err := b.InitGlobalVariable(
			module, "filter_name", programName,
		); err != nil {
			return fmt.Errorf("init global variable: %w", err)
		}
	}

	b.logger.Info("Loading bpf object from module")

	if err := b.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	if b.excludeMountNamespace != 0 {
		excludeMntns, err := b.GetMap(module, "exclude_mntns")
		if err != nil {
			return fmt.Errorf("getting exclude_mntns map failed: %w", err)
		}

		if err := b.UpdateValue(excludeMntns, b.excludeMountNamespace, []byte{excludeMntnsEnabled}); err != nil {
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
			return err
		}
	}

	b.isRecordingBpfMap, err = b.GetMap(b.module, "is_recording")
	if err != nil {
		return fmt.Errorf("getting `is_recording` map: %w", err)
	}

	const timeout = 300

	events := make(chan []byte)

	ringbuf, err := b.InitRingBuf(
		b.module,
		"events",
		events,
	)
	if err != nil {
		return fmt.Errorf("init events ringbuffer: %w", err)
	}

	b.PollRingBuffer(ringbuf, timeout)

	go b.processEvents(events)

	b.logger.Info("BPF module successfully loaded.")

	return nil
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
			return err
		}
	}

	b.logger.Info("Recording started.")

	return nil
}

func (b *BpfRecorder) StopRecording() error {
	b.attachUnattachMutex.Lock()
	defer b.attachUnattachMutex.Unlock()
	b.logger.Info("Stop BPF recording: Detaching all programs...")

	if err := b.UpdateValue(b.isRecordingBpfMap, 0, []byte{1}); err != nil {
		return fmt.Errorf("failed to update `is_recording`: %w", err)
	}

	syscall.Getgid() // Notify BPF program that is_recording has changed.

	if b.Seccomp != nil {
		if err := b.Seccomp.StopRecording(b); err != nil {
			return err
		}
	}

	if b.AppArmor != nil {
		if err := b.AppArmor.StopRecording(b); err != nil {
			return err
		}
	}

	b.logger.Info("Recording stopped.")

	// XXX: It may be useful to clear out all existing maps here.
	return nil
}

func (b *BpfRecorder) findBtfPath() (string, error) {
	// Use the system btf if possible
	if _, err := b.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		b.logger.Info("Using system btf file")

		return "", nil
	}

	b.logger.Info("Trying to find matching in-memory btf")

	btf := types.Btf{}
	if err := b.Unmarshal([]byte(btfJSON), &btf); err != nil {
		return "", fmt.Errorf("unmarshal btf JSON: %w", err)
	}

	res, err := b.ReadOSRelease()
	if err != nil {
		return "", fmt.Errorf("read os-release file: %w", err)
	}

	osID := types.Os(res["ID"])
	btfOs, ok := btf[osID]

	if !ok {
		b.logger.Info(fmt.Sprintf("OS not found in btf map: %s", osID))

		return "", nil
	}

	b.logger.Info(fmt.Sprintf("OS found in btf map: %s", osID))

	osVersion := types.OsVersion(res["VERSION_ID"])
	btfOsVersion, ok := btfOs[osVersion]

	if !ok {
		b.logger.Info(fmt.Sprintf("OS version not found in btf map: %s", osVersion))

		return "", nil
	}

	b.logger.Info(fmt.Sprintf("OS version found in btf map: %s", osVersion))

	uname := syscall.Utsname{}
	if err := b.Uname(&uname); err != nil {
		return "", fmt.Errorf("uname syscall failed: %w", err)
	}

	arch := types.Arch(toStringInt8(uname.Machine))
	btfArch, ok := btfOsVersion[arch]

	if !ok {
		b.logger.Info(fmt.Sprintf("Architecture not found in btf map: %s", arch))

		return "", nil
	}

	b.logger.Info(fmt.Sprintf("Architecture found in btf map: %s", arch))

	release := toStringInt8(uname.Release)

	version, err := semver.Parse(release)
	if err != nil {
		return "", fmt.Errorf("unable to parse semver for release %s: %w", release, err)
	}

	version.Pre = nil

	const (
		lowestMajor = 5
		lowestMinor = 8
	)

	if version.LT(semver.Version{Major: lowestMajor, Minor: lowestMinor}) {
		return "", fmt.Errorf("unsupported kernel version %s: at least Linux 5.8 is required", release)
	}

	kernel := types.Kernel(release)
	btfBytes, ok := btfArch[kernel]

	if !ok {
		b.logger.Info(fmt.Sprintf("Kernel not found in btf map: %s", kernel))

		return "", nil
	}

	b.logger.Info(fmt.Sprintf("Kernel found in btf map: %s", kernel))

	file, err := b.TempFile(
		"",
		fmt.Sprintf("spo-btf-%s-%s-%s-%s", osID, osVersion, arch, kernel),
	)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer file.Close()

	if _, err := b.Write(file, btfBytes); err != nil {
		return "", fmt.Errorf("write BTF: %w", err)
	}

	b.logger.Info("Wrote BTF to file: " + file.Name())

	return file.Name(), nil
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

	err := binary.Read(bytes.NewReader(eventBytes), binary.LittleEndian, &event)
	if err != nil {
		b.logger.Error(err, "Couldn't read event structure")

		return
	}

	switch event.Type {
	case uint8(eventTypeNewPid):
		// handleNewPidEvent can be slow, and we don't want to block the event processing loop.
		go b.handleNewPidEvent(&event)
	case uint8(eventTypeExit):
		b.handleExitEvent(&event)
	case uint8(eventTypeAppArmorFile):
		// b.AppArmor may be null if debug_add_canary_file reports a file event.
		if b.AppArmor != nil {
			b.AppArmor.handleFileEvent(&event)
		}
	case uint8(eventTypeAppArmorSocket):
		b.AppArmor.handleSocketEvent(&event)
	case uint8(eventTypeAppArmorCap):
		b.AppArmor.handleCapabilityEvent(&event)
	case uint8(eventTypeClearMntns):
		if b.AppArmor != nil {
			b.AppArmor.clearMntns(&event)
		}
	}
}

func (b *BpfRecorder) handleNewPidEvent(e *bpfEvent) {
	b.logger.Info(fmt.Sprintf("Received new pid: %d with mntns=%d", e.Pid, e.Mntns))

	pid := e.Pid
	mntns := e.Mntns

	if b.clientset == nil {
		// spoc: we're running outside of a kubernetes context.
		return
	}

	// Look up the container ID based on PID from cgroup file.
	containerID, err := b.ContainerIDForPID(b.pidToContainerIDCache, int(pid))
	if err != nil {
		b.logger.V(config.VerboseLevel).Info(
			"No container ID found for PID",
			"pid", pid, "mntns", mntns, "err", err.Error(),
		)

		return
	}

	b.mntnsToContainerIDMap.Insert(mntns, containerID)

	b.logger.V(config.VerboseLevel).Info(
		"Found container ID for PID", "pid", pid,
		"mntns", mntns, "containerID", containerID,
	)

	profile, err := b.findProfileForContainerID(containerID)
	if err != nil {
		b.logger.Error(err, "Unable to find profile in cluster for container ID",
			"id", containerID, "pid", pid, "mntns", mntns)

		return
	}

	b.logger.Info(
		"Found profile in cluster for container ID", "containerID", containerID,
		"pid", pid, "mntns", mntns, "profile", profile,
	)

	b.trackProfileMetric(mntns, profile)
}

func (b *BpfRecorder) handleExitEvent(exitEvent *bpfEvent) {
	b.logger.Info(fmt.Sprintf("record pid exit: %d.", exitEvent.Pid))
	d, _ := b.recordedExits.LoadOrStore(exitEvent.Pid, make(chan bool))

	done, ok := d.(chan bool)
	if !ok {
		b.logger.Info("unexpected recordedExits type")

		return
	}
	select {
	case <-done:
		// already closed
	default:
		close(done)
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

	ns, err := b.ParseUint(stripped)
	if err != nil {
		return 0, fmt.Errorf("convert namespace to integer: %w", err)
	}

	return ns, nil
}

func (b *BpfRecorder) trackProfileMetric(mntns uint32, profile string) {
	if err := b.SendMetric(b.metricsClient, &apimetrics.BpfRequest{
		Node:           b.nodeName,
		Profile:        profile,
		MountNamespace: mntns,
	}); err != nil {
		b.logger.Error(err, "Unable to update metrics")
	}
}

func (b *BpfRecorder) findProfileForContainerID(id string) (string, error) {
	if profile, ok := b.containerIDToProfileMap.Get(id); ok {
		b.logger.Info("Found profile in cache", "containerID", id, "profile", profile)

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
			b.logger.Info("Looking up container ID in cluster", "id", id, "try", try)
			pods, err := b.ListPods(ctx, b.clientset, b.nodeName)
			if err != nil {
				return fmt.Errorf("list node pods: %w", err)
			}
			if pods == nil {
				return errors.New("no pods found in cluster")
			}

			for p := range pods.Items {
				pod := &pods.Items[p]
				//nolint:gocritic // We explicitly do not want to append to the same slice
				statuses := append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...)
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

	return "", fmt.Errorf("container ID not found: %s", id)
}

// When running outside of Kubernetes as spoc, we have the use case of waiting for a specific PID to exit.
func (b *BpfRecorder) WaitForPidExit(ctx context.Context, pid uint32) error {
	d, _ := b.recordedExits.LoadOrStore(pid, make(chan bool))
	done, ok := d.(chan bool)

	if !ok {
		return fmt.Errorf("unexpected type: %T", d)
	}

	select {
	case <-done:
	case <-ctx.Done():
		return fmt.Errorf("waiting for pid exit: %w", ctx.Err())
	}

	return nil
}

func BPFLSMEnabled() bool {
	contents, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}

	return regexp.MustCompile(`(^|,)bpf(,|$)`).Match(contents)
}
