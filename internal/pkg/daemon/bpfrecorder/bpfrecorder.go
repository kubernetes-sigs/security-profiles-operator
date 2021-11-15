//go:build linux
// +build linux

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

	"github.com/ReneKroon/ttlcache/v2"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	seccomp "github.com/seccomp/libseccomp-golang"
	"google.golang.org/grpc"
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
	verboseLvl          int           = 1
	backoffDuration                   = 500 * time.Millisecond
	backoffFactor                     = 1.5
	backoffSteps                      = 10
)

// BpfRecorder is the main structure of this package.
type BpfRecorder struct {
	api.UnimplementedBpfRecorderServer
	impl
	logger                   logr.Logger
	startRequests            int64
	syscalls                 *bpf.BPFMap
	comms                    *bpf.BPFMap
	btfPath                  string
	syscallNamesForIDCache   ttlcache.SimpleCache
	containerIDCache         ttlcache.SimpleCache
	nodeName                 string
	clientset                *kubernetes.Clientset
	profileForContainerIDs   sync.Map
	pidsForProfiles          sync.Map
	profileForMountNamespace sync.Map
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
		impl:                     &defaultImpl{},
		logger:                   logger,
		syscallNamesForIDCache:   ttlcache.NewCache(),
		containerIDCache:         ttlcache.NewCache(),
		profileForContainerIDs:   sync.Map{},
		pidsForProfiles:          sync.Map{},
		profileForMountNamespace: sync.Map{},
		loadUnloadMutex:          sync.RWMutex{},
	}
}

// Run the BpfRecorder.
func (b *BpfRecorder) Run() error {
	b.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))
	for _, cache := range []ttlcache.SimpleCache{
		b.containerIDCache, b.syscallNamesForIDCache,
	} {
		if err := b.SetTTL(cache, defaultCacheTimeout); err != nil {
			return errors.Wrap(err, "set cache timeout")
		}
		defer cache.Close()
	}

	b.nodeName = b.Getenv(config.NodeNameEnvKey)
	if b.nodeName == "" {
		err := errors.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		b.logger.Error(err, "unable to run recorder")
		return err
	}
	b.logger.Info("Starting log-enricher on node: " + b.nodeName)

	clusterConfig, err := b.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "get in-cluster config")
	}

	b.clientset, err = b.NewForConfig(clusterConfig)
	if err != nil {
		return errors.Wrap(err, "load in-cluster client")
	}

	if _, err := b.Stat(config.GRPCServerSocketBpfRecorder); err == nil {
		if err := b.RemoveAll(config.GRPCServerSocketBpfRecorder); err != nil {
			return errors.Wrap(err, "remove GRPC socket file")
		}
	}

	listener, err := b.Listen("unix", config.GRPCServerSocketBpfRecorder)
	if err != nil {
		return errors.Wrap(err, "create listener")
	}

	if err := b.Chown(
		config.GRPCServerSocketBpfRecorder,
		config.UserRootless,
		config.UserRootless,
	); err != nil {
		return errors.Wrap(err, "change GRPC socket owner to rootless")
	}

	b.logger.Info("Connecting to metrics server")
	conn, cancel, err := b.connectMetrics()
	if err != nil {
		return errors.Wrap(err, "connect to metrics server")
	}
	if cancel != nil {
		defer cancel()
	}
	if conn != nil {
		defer b.CloseGRPC(conn) // nolint: errcheck
	}

	b.systemMountNamespace, err = b.findSystemMountNamespace()
	if err != nil {
		return errors.Wrap(err, "retrieve current mount namespace")
	}
	b.logger.Info("Got system mount namespace: " + fmt.Sprint(b.systemMountNamespace))

	b.logger.Info("Doing BPF load/unload self-test")
	if err := b.load(); err != nil {
		return errors.Wrap(err, "load self-test")
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
			return errors.Wrap(err, "connecting to local metrics GRPC server")
		}
		client := apimetrics.NewMetricsClient(conn)

		b.metricsClient, err = b.BpfIncClient(client)
		if err != nil {
			cancel()
			if err := b.CloseGRPC(conn); err != nil {
				b.logger.Error(err, "Unable to close GRPC connection")
			}
			return errors.Wrap(err, "create metrics bpf client")
		}

		return nil
	}, func(err error) bool { return true }); err != nil {
		return nil, nil, errors.Wrap(err, "connect to local GRPC server")
	}

	return conn, cancel, nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	conn, err := grpc.DialContext(ctx, "unix://"+config.GRPCServerSocketBpfRecorder, grpc.WithInsecure())
	if err != nil {
		cancel()
		return nil, nil, errors.Wrap(err, "GRPC dial")
	}
	return conn, cancel, nil
}

func (b *BpfRecorder) Start(
	ctx context.Context, r *api.EmptyRequest,
) (*api.EmptyResponse, error) {
	if b.startRequests == 0 {
		b.logger.Info("Starting bpf recorder")
		if err := b.load(); err != nil {
			return nil, errors.Wrap(err, "load bpf")
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

	res, exist := b.pidsForProfiles.LoadAndDelete(r.Name)
	if !exist {
		return nil, ErrNotFound
	}
	pids, ok := res.([]Pid)
	if !ok {
		return nil, errors.New("result it not a pid type")
	}
	b.logger.Info(fmt.Sprintf("Got PIDs for the profile: %v", pids))
	if len(pids) == 0 {
		return nil, errors.Errorf("PID slice is empty")
	}

	result := []string{}
	for _, pid := range pids {
		b.profileForMountNamespace.Delete(pid.mntns)

		b.loadUnloadMutex.RLock()
		syscalls, err := b.GetValue(b.syscalls, pid.id)
		b.loadUnloadMutex.RUnlock()
		if err != nil {
			b.logger.Error(err, "no syscalls found for PID", "pid", pid.id)
			continue
		}

		for id, set := range syscalls {
			if set == 1 {
				name, err := b.syscallNameForID(id)
				if err != nil {
					b.logger.Error(err, "unable to convert syscall ID")
					continue
				}

				b.logger.V(verboseLvl).Info(
					"Got syscall",
					"comm", pid.comm, "pid", pid.id, "name", name,
				)
				result = append(result, name)
			}
		}
	}

	// Cleanup hashmaps
	b.logger.Info("Cleaning up BPF hashmaps")
	for _, pid := range pids {
		b.loadUnloadMutex.Lock()
		if err := b.DeleteKey(b.comms, pid.id); err != nil {
			b.logger.Error(err, "unable to cleanup comms map", "pid", pid.id)
		}
		b.loadUnloadMutex.Unlock()
	}

	return &api.SyscallsResponse{
		Syscalls: sortUnique(result),
		GoArch:   runtime.GOARCH,
	}, nil
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

func (b *BpfRecorder) load() (err error) {
	b.logger.Info("Loading bpf module")
	b.btfPath, err = b.findBtfPath()
	if err != nil {
		return errors.Wrap(err, "find btf")
	}

	bpfObject, ok := bpfObjects[b.GoArch()]
	if !ok {
		return errors.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
	}

	module, err := b.NewModuleFromBufferArgs(&bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
		BTFObjPath: b.btfPath,
	})
	if err != nil {
		return errors.Wrap(err, "load bpf module")
	}

	b.logger.Info("Loading bpf object from module")
	if err := b.BPFLoadObject(module); err != nil {
		return errors.Wrap(err, "load bpf object")
	}

	const programName = "sys_enter"
	b.logger.Info("Getting bpf program " + programName)
	program, err := b.GetProgram(module, programName)
	if err != nil {
		return errors.Wrapf(err, "get %s program", programName)
	}

	b.logger.Info("Attaching bpf tracepoint")
	if _, err := b.AttachTracepoint(program, "raw_syscalls", programName); err != nil {
		return errors.Wrap(err, "attach tracepoint")
	}

	b.logger.Info("Getting syscalls map")
	syscalls, err := b.GetMap(module, "syscalls")
	if err != nil {
		return errors.Wrap(err, "get syscalls map")
	}

	b.logger.Info("Getting comms map")
	comms, err := b.GetMap(module, "comms")
	if err != nil {
		return errors.Wrap(err, "get comms map")
	}

	events := make(chan []byte)
	ringbuffer, err := b.InitRingBuf(module, "events", events)
	if err != nil {
		return errors.Wrap(err, "init events ringbuffer")
	}
	b.StartRingBuffer(ringbuffer)

	b.syscalls = syscalls
	b.comms = comms
	go b.processEvents(events)

	b.logger.Info("Module successfully loaded, watching for events")
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
		return "", errors.Wrap(err, "unmarshal btf JSON")
	}

	res, err := b.ReadOSRelease()
	if err != nil {
		return "", errors.Wrap(err, "read os-release file")
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
		return "", errors.Wrap(err, "uname syscall failed")
	}

	arch := types.Arch(toStringInt8(uname.Machine))
	btfArch, ok := btfOsVersion[arch]
	if !ok {
		b.logger.Info(fmt.Sprintf("Architecture not found in btf map: %s", arch))
		return "", nil
	}
	b.logger.Info(fmt.Sprintf("Architecture found in btf map: %s", arch))

	kernel := types.Kernel(toStringInt8(uname.Release))
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
		return "", errors.Wrap(err, "create temp file")
	}
	defer file.Close()

	if _, err := b.Write(file, btfBytes); err != nil {
		return "", errors.Wrap(err, "write BTF")
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
	for event := range events {
		// Newly arrived PIDs
		const eventLen = 16
		if len(event) != eventLen {
			b.logger.Info("Invalid event length", "len", len(event))
			continue
		}

		pid := binary.LittleEndian.Uint32(event)
		mntns := binary.LittleEndian.Uint64(event[8:])

		// Filter out non-containers
		if mntns == b.systemMountNamespace {
			b.logger.V(verboseLvl).Info(
				"Skipping PID, because it's on the system mount namespace",
				"pid", pid, "mntns", mntns,
			)
			continue
		}

		// Short path via the mount namespace
		if profile, exist := b.profileForMountNamespace.Load(mntns); exist {
			b.logger.Info(
				"Using short path via tracked mount namespace",
				"pid", pid, "mntns", mntns, "profile", profile,
			)
			b.trackProfileForPid(pid, mntns, profile)
			continue
		}

		// Regular container ID retrieval via the cgroup
		containerID, err := b.ContainerIDForPID(b.containerIDCache, int(pid))
		if err != nil {
			b.logger.V(verboseLvl).Info(
				"No container ID found for PID",
				"pid", pid, "err", err.Error(),
			)
			continue
		}

		b.logger.V(verboseLvl).Info(
			"Found container for PID", "pid", pid, "containerID", containerID,
		)
		if err := b.findContainerID(containerID); err != nil {
			b.logger.Error(err, "unable to find container ID in cluster")
			continue
		}

		if profile, exist := b.profileForContainerIDs.LoadAndDelete(containerID); exist {
			b.logger.Info(
				"Saving PID for profile",
				"pid", pid, "mntns", mntns, "profile", profile,
			)
			b.trackProfileForPid(pid, mntns, profile)
			b.profileForMountNamespace.Store(mntns, profile)
		}
	}
}

func (b *BpfRecorder) findSystemMountNamespace() (uint64, error) {
	// This requires the container to run with host PID, otherwise we will get
	// the namespace from the container.
	res, err := b.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return 0, errors.Wrap(err, "read mount namespace link")
	}
	stripped := strings.TrimPrefix(res, "mnt:[")
	stripped = strings.TrimSuffix(stripped, "]")

	ns, err := b.Atoi(stripped)
	if err != nil {
		return 0, errors.Wrap(err, "convert namespace to integer")
	}

	return uint64(ns), nil
}

func (b *BpfRecorder) trackProfileForPid(pid uint32, mntns uint64, profile interface{}) {
	comm := b.commForPid(pid)

	if err := b.SendMetric(b.metricsClient, &apimetrics.BpfRequest{
		Node:           b.nodeName,
		Profile:        profile.(string),
		MountNamespace: mntns,
	}); err != nil {
		b.logger.Error(err, "Unable to update metrics")
	}

	pids, _ := b.pidsForProfiles.LoadOrStore(profile, []Pid{})
	b.pidsForProfiles.Store(profile, append(
		pids.([]Pid), Pid{id: pid, comm: comm, mntns: mntns}),
	)
}

func (b *BpfRecorder) commForPid(pid uint32) string {
	b.loadUnloadMutex.RLock()
	rawComm, err := b.GetValue(b.comms, pid)
	b.loadUnloadMutex.RUnlock()
	if err != nil {
		b.logger.Error(err, "unable to get command name for PID", "pid", pid)
	}
	return toStringByte(rawComm)
}

func (b *BpfRecorder) findContainerID(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	errContainerIDNotFound := errors.New("container ID not found")

	if err := util.RetryEx(
		&wait.Backoff{
			Duration: backoffDuration,
			Factor:   backoffFactor,
			Steps:    backoffSteps,
		},
		func() (retryErr error) {
			b.logger.V(verboseLvl).Info("Searching for in-cluster container ID: " + id)

			pods, err := b.ListPods(ctx, b.clientset, b.nodeName)
			if err != nil {
				return errors.Wrapf(err, "list node pods")
			}

			for p := range pods.Items {
				pod := &pods.Items[p]
				for c := range pod.Status.ContainerStatuses {
					containerStatus := pod.Status.ContainerStatuses[c]
					fullContainerID := containerStatus.ContainerID
					containerName := containerStatus.Name

					// An empty container ID should not happen if the PID is already running,
					// so this is most likely not the pod we're looking for
					if fullContainerID == "" {
						b.logger.V(verboseLvl).Info(
							"No container ID available",
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
						b.logger.V(verboseLvl).Info(
							"Found profile to record",
							"profile", profile,
							"containerID", containerID,
							"containerName", containerName,
						)
						b.profileForContainerIDs.Store(containerID, profile)
					}

					if containerID == id {
						b.logger.Info(
							"Found container ID in cluster",
							"containerID", containerID,
							"containerName", containerName,
						)
						return nil
					}
				}
			}

			return errContainerIDNotFound
		},
		func(inErr error) bool {
			return errors.Is(inErr, errContainerIDNotFound)
		},
	); err != nil {
		return errors.Wrap(err, "find container ID")
	}

	return nil
}

func (b *BpfRecorder) unload() {
	b.logger.Info("Unloading bpf module")
	b.loadUnloadMutex.Lock()
	b.CloseModule(b.syscalls)
	b.syscalls = nil
	b.comms = nil
	os.RemoveAll(b.btfPath)
	b.loadUnloadMutex.Unlock()
}

func (b *BpfRecorder) syscallNameForID(id int) (string, error) {
	// Check the cache first
	key := strconv.Itoa(id)
	if name, err := b.syscallNamesForIDCache.Get(key); !errors.Is(
		err, ttlcache.ErrNotFound,
	) {
		return name.(string), nil
	}

	name, err := b.GetName(seccomp.ScmpSyscall(id))
	if err != nil {
		return "", errors.Wrapf(err, "get syscall name for ID %d", id)
	}

	if err := b.syscallNamesForIDCache.Set(key, name); err != nil {
		return "", errors.Wrap(err, "update cache")
	}
	return name, nil
}
