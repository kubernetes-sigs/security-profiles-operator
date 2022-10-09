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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
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
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	defaultTimeout      time.Duration = time.Minute
	maxMsgSize          int           = 16 * 1024 * 1024
	defaultCacheTimeout time.Duration = time.Hour
	maxCacheItems       uint64        = 1000
	defaultHostPid      uint32        = 1
	defaultByteNum      int           = 8
)

// BpfRecorder is the main structure of this package.
type BpfRecorder struct {
	api.UnimplementedBpfRecorderServer
	impl
	logger                   logr.Logger
	startRequests            int64
	syscalls                 *bpf.BPFMap
	comms                    *bpf.BPFMap
	mntns                    *bpf.BPFMap
	record                   *bpf.BPFMap
	btfPath                  string
	syscallNamesForIDCache   *ttlcache.Cache[string, string]
	containerIDCache         *ttlcache.Cache[string, string]
	nodeName                 string
	clientset                *kubernetes.Clientset
	profileForMountNamespace sync.Map
	mntnsForProfile          sync.Map
	mntnsLock                sync.Mutex
	systemMountNamespace     uint64
	loadUnloadMutex          sync.RWMutex
	metricsClient            apimetrics.Metrics_BpfIncClient
}

type Pid struct {
	id    uint32
	comm  string
	mntns uint64
}

// New returns a new BpfRecorder instance.
func New(logger logr.Logger) *BpfRecorder {
	return &BpfRecorder{
		impl:   &defaultImpl{},
		logger: logger,
		syscallNamesForIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		containerIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		mntnsLock:                sync.Mutex{},
		profileForMountNamespace: sync.Map{},
		mntnsForProfile:          sync.Map{},
		loadUnloadMutex:          sync.RWMutex{},
	}
}

// Run the BpfRecorder.
func (b *BpfRecorder) Run() error {
	b.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))
	for _, cache := range []*ttlcache.Cache[string, string]{
		b.containerIDCache, b.syscallNamesForIDCache,
	} {
		go cache.Start()
	}

	b.nodeName = b.Getenv(config.NodeNameEnvKey)
	if b.nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		b.logger.Error(err, "unable to run recorder")
		return err
	}
	b.logger.Info("Starting log-enricher on node: " + b.nodeName)

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

	b.systemMountNamespace, err = b.findSystemMountNamespace()
	if err != nil {
		return fmt.Errorf("retrieve current mount namespace: %w", err)
	}
	b.logger.Info("Got system mount namespace: " + fmt.Sprint(b.systemMountNamespace))

	b.logger.Info("Doing BPF load/unload self-test")
	if err := b.load(false); err != nil {
		return fmt.Errorf("load self-test: %w", err)
	}
	b.unload()

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
	ctx context.Context, r *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	if b.startRequests == 0 {
		b.logger.Info("Starting bpf recorder")
		if err := b.load(true); err != nil {
			return nil, fmt.Errorf("load bpf: %w", err)
		}
	} else {
		b.logger.Info("bpf recorder already running")
	}

	atomic.AddInt64(&b.startRequests, 1)
	return &api.EmptyResponse{}, nil
}

func (b *BpfRecorder) Stop(
	ctx context.Context, r *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	if b.startRequests == 0 {
		b.logger.Info("bpf recorder not running")
		return &api.EmptyResponse{}, nil
	}

	atomic.AddInt64(&b.startRequests, -1)
	if b.startRequests == 0 {
		b.logger.Info("Stopping bpf recorder")
		b.unload()
	} else {
		b.logger.Info("Not stopping because another recording is in progress")
	}
	return &api.EmptyResponse{}, nil
}

// SyscallsForProfile returns the syscall names for the provided PID.
func (b *BpfRecorder) SyscallsForProfile(
	ctx context.Context, r *api.ProfileRequest,
) (*api.SyscallsResponse, error) {
	if b.startRequests == 0 {
		return nil, errors.New("bpf recorder not running")
	}
	b.logger.Info("Getting syscalls for profile " + r.Name)

	// There is a chance to miss the PID if concurrent processes are being
	// analyzed. If we request the `SyscallsForProfile` exactly between two
	// events, while the first one is from a different recording container and
	// we have to expect the profile in the second event. We try to overcome
	// this race by retrying, but with a more loose backoff strategy than
	// retrying to retrieve the in-cluster container ID.
	var (
		mntns interface{}
		exist bool
		try   = -1
	)
	if err := util.Retry(
		func() error {
			try++
			b.logger.Info(
				"Looking up PID for profile", "try", try, "profile", r.Name,
			)

			b.mntnsLock.Lock()
			mntns, exist = b.mntnsForProfile.LoadAndDelete(r.Name)
			if !exist {
				return ErrNotFound
			}
			b.profileForMountNamespace.Delete(mntns.(uint64))
			b.mntnsLock.Unlock()

			return nil
		},
		func(error) bool { return true },
	); err != nil {
		return nil, ErrNotFound
	}

	b.loadUnloadMutex.RLock()
	//get syscall from ebpf syscalls map by mntns
	syscalls, err := b.GetValue64(b.syscalls, mntns.(uint64))
	b.loadUnloadMutex.RUnlock()
	if err != nil {
		b.logger.Error(err, "no syscalls found for mntns", "mntns", mntns.(uint64))
		return nil, ErrNotFound
	}
	result := b.getSyscallName(syscalls)
	b.logger.Info("collect syscalls for profile success", "profile", r.Name, "mntns", mntns.(uint64), "syscall size", len(result), "syscalls", result)

	// Cleanup hashmaps
	b.logger.Info("Cleaning up BPF hashmaps")
	b.loadUnloadMutex.Lock()
	if err := b.DeleteKey64(b.syscalls, mntns.(uint64)); err != nil {
		b.logger.Error(err, "unable to cleanup mntns syscall map", "mntns", mntns.(uint64))
	}
	if err := b.DeleteKey64(b.record, mntns.(uint64)); err != nil {
		b.logger.Error(err, "unable to cleanup mntns syscall map", "mntns", mntns.(uint64))
	}
	b.loadUnloadMutex.Unlock()

	return &api.SyscallsResponse{
		Syscalls: sortUnique(result),
		GoArch:   runtime.GOARCH,
	}, nil
}

func (b *BpfRecorder) getSyscallName(syscalls []byte) []string {
	result := []string{}
	for id, set := range syscalls {
		if set == 1 {
			name, err := b.syscallNameForID(id)
			if err != nil {
				b.logger.Error(err, "unable to convert syscall ID")
				continue
			}
			result = append(result, name)
		}
	}
	return result
}

func sortUnique(input []string) (res []string) {
	tmp := map[string]bool{}
	for _, val := range input {
		tmp[val] = true
	}
	for k := range tmp {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}

func (b *BpfRecorder) load(startEventProcessor bool) (err error) {
	b.logger.Info("Loading bpf module")
	b.btfPath, err = b.findBtfPath()
	if err != nil {
		return fmt.Errorf("find btf: %w", err)
	}

	bpfObject, ok := bpfObjects[b.GoArch()]
	if !ok {
		return fmt.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
	}

	module, err := b.NewModuleFromBufferArgs(&bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
		BTFObjPath: b.btfPath,
	})
	if err != nil {
		return fmt.Errorf("load bpf module: %w", err)
	}

	b.logger.Info("Loading bpf object from module")
	if err := b.BPFLoadObject(module); err != nil {
		return fmt.Errorf("load bpf object: %w", err)
	}

	const programName = "sys_enter"
	b.logger.Info("Getting bpf program " + programName)
	program, err := b.GetProgram(module, programName)
	if err != nil {
		return fmt.Errorf("get %s program: %w", programName, err)
	}

	b.logger.Info("Attaching bpf tracepoint")
	if _, err := b.AttachTracepoint(program, "raw_syscalls", programName); err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}

	b.logger.Info("Getting syscalls map")
	syscalls, err := b.GetMap(module, "mntns_syscalls")
	if err != nil {
		return fmt.Errorf("get syscalls map: %w", err)
	}

	b.logger.Info("Getting comms map")
	comms, err := b.GetMap(module, "comms")
	if err != nil {
		return fmt.Errorf("get comms map: %w", err)
	}
	b.logger.Info("Getting system_mntns map")
	mntns, err := b.GetMap(module, "system_mntns")
	if err != nil {
		return fmt.Errorf("get mntns map: %w", err)
	}
	b.logger.Info("Getting mntns_record map")
	record, err := b.GetMap(module, "mntns_record")
	if err != nil {
		return fmt.Errorf("get record map: %w", err)
	}

	// Update mntns to system_mntns
	b.updateSystemMntns(mntns)

	events := make(chan []byte)
	ringbuffer, err := b.InitRingBuf(module, "events", events)
	if err != nil {
		return fmt.Errorf("init events ringbuffer: %w", err)
	}
	b.StartRingBuffer(ringbuffer)

	b.syscalls = syscalls
	b.comms = comms
	b.mntns = mntns
	b.record = record

	if startEventProcessor {
		go b.processEvents(events)
	}

	b.logger.Info("Module successfully loaded")
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

	b.logger.Info(fmt.Sprintf("Wrote BTF to file: %s", file.Name()))
	return file.Name(), nil
}

func toStringInt8(array [65]int8) string {
	var buf [65]byte
	for i, b := range array {
		buf[i] = byte(b)
	}
	return toStringByte(buf[:])
}

func toStringByte(array []byte) string {
	str := string(array)
	if i := strings.Index(str, "\x00"); i != -1 {
		str = str[:i]
	}
	return str
}

func (b *BpfRecorder) processEvents(events chan []byte) {
	b.logger.Info("Processing events")

	// Allow up to 1000 goroutines to run in parallel
	const workers = 1000
	sem := semaphore.NewWeighted(workers)

	for event := range events {
		if err := sem.Acquire(context.Background(), 1); err != nil {
			b.logger.Error(err, "Unable to acquire semaphore, stopping event processor")
			break
		}
		eventCopy := event
		go func() {
			b.handleEvent(eventCopy)
			sem.Release(1)
		}()
	}
}

func (b *BpfRecorder) updateSystemMntns(bpfMap *bpf.BPFMap) {
	mntnsByte := make([]byte, defaultByteNum)
	binary.LittleEndian.PutUint64(mntnsByte, b.systemMountNamespace)
	err := b.UpdateValue(bpfMap, defaultHostPid, mntnsByte)
	if err != nil {
		b.logger.Error(err, "update system_mntns map failed")
	}
}

func (b *BpfRecorder) updateRecord(mntns uint64) {
	b.logger.Info("update mntns to mntns_record map", "mntns", mntns)
	var record uint8 = 1
	b.loadUnloadMutex.Lock()
	err := b.UpdateValue8(b.record, mntns, record)
	b.loadUnloadMutex.Unlock()
	if err != nil {
		b.logger.Error(err, "update mntns_record map failed")
	}
}

func (b *BpfRecorder) handleEvent(event []byte) {
	// Newly arrived PIDs
	const eventLen = 16
	if len(event) != eventLen {
		b.logger.Info("Invalid event length", "len", len(event))
		return
	}

	pid := binary.LittleEndian.Uint32(event)
	mntns := binary.LittleEndian.Uint64(event[8:])

	// Blocking from syscall retrieval when PIDs are currently being analyzed
	b.mntnsLock.Lock()
	defer b.mntnsLock.Unlock()

	// Short path via the mount namespace
	if profile, exist := b.profileForMountNamespace.Load(mntns); exist {
		b.logger.Info(
			"Skipping PID, because it has already on the mount namespace",
			"pid", pid, "mntns", mntns, "profile", profile,
		)
		return
	}

	// Regular container ID retrieval via the cgroup
	containerID, err := b.ContainerIDForPID(b.containerIDCache, int(pid))
	if err != nil {
		b.logger.V(config.VerboseLevel).Info(
			"No container ID found for PID",
			"pid", pid, "err", err.Error(),
		)
		return
	}
	b.updateRecord(mntns)

	b.logger.V(config.VerboseLevel).Info(
		"Found container for PID", "pid", pid, "containerID", containerID,
	)
	if err := b.findContainerID(containerID, mntns); err != nil {
		b.logger.Error(err, "unable to find container ID in cluster")
		return
	}

}

func (b *BpfRecorder) findSystemMountNamespace() (uint64, error) {
	// This requires the container to run with host PID, otherwise we will get
	// the namespace from the container.
	res, err := b.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return 0, fmt.Errorf("read mount namespace link: %w", err)
	}
	stripped := strings.TrimPrefix(res, "mnt:[")
	stripped = strings.TrimSuffix(stripped, "]")

	ns, err := b.Atoi(stripped)
	if err != nil {
		return 0, fmt.Errorf("convert namespace to integer: %w", err)
	}

	return uint64(ns), nil
}

func (b *BpfRecorder) trackProfileForMntns(mntns uint64, profile string) {
	if err := b.SendMetric(b.metricsClient, &apimetrics.BpfRequest{
		Node:           b.nodeName,
		Profile:        profile,
		MountNamespace: mntns,
	}); err != nil {
		b.logger.Error(err, "Unable to update metrics")
	}
}

func (b *BpfRecorder) findContainerID(id string, mntns uint64) error {
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
			b.logger.Info("Looking up in-cluster container ID", "id", id, "try", try)
			pods, err := b.ListPods(ctx, b.clientset, b.nodeName)
			if err != nil {
				return fmt.Errorf("list node pods: %w", err)
			}

			for p := range pods.Items {
				pod := &pods.Items[p]
				for c := range pod.Status.ContainerStatuses {
					containerStatus := pod.Status.ContainerStatuses[c]
					fullContainerID := containerStatus.ContainerID
					containerName := containerStatus.Name

					// It's possible that the container ID is not yet set, but
					// we cannot be sure since we have to test against the
					// `id`.
					if fullContainerID == "" {
						b.logger.Info(
							"Container ID not yet available",
							"podName", pod.Name,
							"containerName", containerName,
						)
						continue
					}

					containerID := util.ContainerIDRegex.FindString(fullContainerID)
					if containerID == "" {
						b.logger.Error(err,
							"unable to get container ID",
							"podName", pod.Name,
							"containerName", containerName,
						)
						continue
					}

					key := config.SeccompProfileRecordBpfAnnotationKey + containerName
					if profile, ok := pod.Annotations[key]; ok {
						if containerID == id {
							b.logger.V(config.VerboseLevel).Info(
								"Found profile to record",
								"profile", profile,
								"containerID", containerID,
								"containerName", containerName,
								"mntns", mntns,
							)
							b.mntnsForProfile.Store(profile, mntns)
							b.profileForMountNamespace.Store(mntns, profile)
							b.trackProfileForMntns(mntns, profile)
							return nil
						}
					}
				}
			}

			return errors.New("container ID not found")
		},
		func(error) bool { return true },
	); err != nil {
		return fmt.Errorf("find container ID: %w", err)
	}

	return nil
}

func (b *BpfRecorder) unload() {
	b.logger.Info("Unloading bpf module")
	b.loadUnloadMutex.Lock()
	b.CloseModule(b.syscalls)
	b.syscalls = nil
	b.comms = nil
	b.mntns = nil
	b.record = nil
	os.RemoveAll(b.btfPath)
	b.loadUnloadMutex.Unlock()
}

func (b *BpfRecorder) syscallNameForID(id int) (string, error) {
	// Check the cache first
	key := strconv.Itoa(id)
	item := b.syscallNamesForIDCache.Get(key)
	if item != nil {
		return item.Value(), nil
	}

	name, err := b.GetName(seccomp.ScmpSyscall(id))
	if err != nil {
		return "", fmt.Errorf("get syscall name for ID %d: %w", id, err)
	}

	b.syscallNamesForIDCache.Set(key, name, ttlcache.DefaultTTL)
	return name, nil
}
