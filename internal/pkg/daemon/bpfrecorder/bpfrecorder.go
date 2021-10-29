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
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/ReneKroon/ttlcache/v2"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/cobaugh/osrelease"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	seccomp "github.com/seccomp/libseccomp-golang"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "sigs.k8s.io/security-profiles-operator/api/grpc/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

//go:generate go run ./generate

const (
	defaultTimeout      time.Duration = time.Minute
	maxMsgSize          int           = 16 * 1024 * 1024
	defaultCacheTimeout time.Duration = time.Hour
)

// BpfRecorder is the main structure of this package.
type BpfRecorder struct {
	api.UnimplementedBpfRecorderServer
	logger                 logr.Logger
	startRequests          int64
	syscalls               *bpf.BPFMap
	pids                   *bpf.BPFMap
	comms                  *bpf.BPFMap
	btfPath                string
	syscallNamesForIDCache ttlcache.SimpleCache
	containerIDCache       ttlcache.SimpleCache
	nodeName               string
	clientset              *kubernetes.Clientset
	profileForContainerIDs sync.Map
	pidsForProfiles        sync.Map
}

type Pid struct {
	id   uint32
	comm string
}

// New returns a new BpfRecorder instance.
func New(logger logr.Logger) *BpfRecorder {
	return &BpfRecorder{
		logger:                 logger,
		syscallNamesForIDCache: ttlcache.NewCache(),
		containerIDCache:       ttlcache.NewCache(),
		profileForContainerIDs: sync.Map{},
		pidsForProfiles:        sync.Map{},
	}
}

// Run the BpfRecorder.
func (b *BpfRecorder) Run() error {
	b.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))
	for _, cache := range []ttlcache.SimpleCache{
		b.containerIDCache, b.syscallNamesForIDCache,
	} {
		if err := cache.SetTTL(defaultCacheTimeout); err != nil {
			return errors.Wrap(err, "set cache timeout")
		}
		defer cache.Close()
	}

	b.nodeName = os.Getenv(config.NodeNameEnvKey)
	if b.nodeName == "" {
		err := errors.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		b.logger.Error(err, "unable to run recorder")
		return err
	}
	b.logger.Info("Starting log-enricher on node: " + b.nodeName)

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return errors.Wrap(err, "get in-cluster config")
	}

	b.clientset, err = kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return errors.Wrap(err, "load in-cluster client")
	}

	listener, err := net.Listen("tcp", addr())
	if err != nil {
		return errors.Wrap(err, "create listener")
	}

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

	if err := grpcServer.Serve(listener); err != nil {
		b.logger.Error(err, "unable to run GRPC server")
	}

	return nil
}

// Dial can be used to connect to the default GRPC server by creating a new
// client.
func Dial() (*grpc.ClientConn, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	conn, err := grpc.DialContext(ctx, addr(), grpc.WithInsecure())
	if err != nil {
		cancel()
		return nil, nil, errors.Wrap(err, "GRPC dial")
	}
	return conn, cancel, nil
}

// addr returns the default server listening address.
func addr() string {
	return net.JoinHostPort("localhost", "9112")
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

// SyscallsForNamespace returns the syscall names for the provided PID.
func (b *BpfRecorder) SyscallsForProfile(
	ctx context.Context, r *api.ProfileRequest,
) (*api.SyscallsResponse, error) {
	if b.startRequests == 0 {
		return nil, errors.New("bpf recorder not running")
	}
	b.logger.Info("Getting syscalls for profile " + r.Name)

	res, exist := b.pidsForProfiles.LoadAndDelete(r.Name)
	if !exist {
		return nil, errors.Errorf("no PID found for container")
	}
	pids := res.([]Pid)
	b.logger.Info(fmt.Sprintf("Got PIDs for the profile: %v", pids))
	if len(pids) == 0 {
		return nil, errors.Errorf("PID slice is empty")
	}

	// We're just choosing the first PID because their mount namespace should
	// be the same (last famous words).
	mntns, err := b.mountNamespaceForPID(pids[0].id)
	if err != nil {
		return nil, errors.Wrapf(err, "get mount namespace")
	}

	mntnsKey := unsafe.Pointer(&mntns)
	syscalls, err := b.syscalls.GetValue(mntnsKey)
	if err != nil {
		return nil, errors.Wrap(err, "no syscalls found for namespace")
	}

	resp := &api.SyscallsResponse{}
	prctlSeen := false
	for id, set := range syscalls {
		if set == 1 {
			name, err := b.syscallNameForID(id)
			if err != nil {
				b.logger.Error(err, "unable to convert syscall ID")
				continue
			}

			// We only start recording the syscalls from the call to prctl
			// within the OCI runtime.
			if name == "prctl" {
				prctlSeen = true
			}

			if prctlSeen {
				resp.Syscalls = append(resp.Syscalls, name)
			}
		}
	}
	sort.Strings(resp.Syscalls)

	// Cleanup hashmaps
	b.logger.Info("Cleaning up BPF hashmaps")
	if err := b.syscalls.DeleteKey(mntnsKey); err != nil {
		b.logger.Error(err, "unable to cleanup mount namespaces map")
	}
	for _, pid := range pids {
		p := pid.id
		if err := b.pids.DeleteKey(unsafe.Pointer(&p)); err != nil {
			b.logger.Error(err, "unable to cleanup PIDs map", "pid", pid.id)
		}
		if err := b.comms.DeleteKey(unsafe.Pointer(&p)); err != nil {
			b.logger.Error(err, "unable to cleanup comms map", "pid", pid.id)
		}
	}

	return resp, nil
}

func (b *BpfRecorder) load() (err error) {
	b.logger.Info("Loading bpf module")
	b.btfPath, err = b.findBtfPath()
	if err != nil {
		return errors.Wrap(err, "find btf")
	}

	bpfObject, ok := bpfObjects[runtime.GOARCH]
	if !ok {
		return errors.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
	}

	module, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "recorder.bpf.o",
		BTFObjPath: b.btfPath,
	})
	if err != nil {
		return errors.Wrap(err, "load bpf module")
	}

	b.logger.Info("Loading bpf object from module")
	if err := module.BPFLoadObject(); err != nil {
		return errors.Wrap(err, "load bpf object")
	}

	const programName = "sys_exit"
	b.logger.Info("Getting bpf program " + programName)
	program, err := module.GetProgram(programName)
	if err != nil {
		return errors.Wrapf(err, "get %s program", programName)
	}

	b.logger.Info("Attaching bpf tracepoint")
	if _, err := program.AttachTracepoint("raw_syscalls", programName); err != nil {
		return errors.Wrap(err, "attach tracepoint")
	}

	b.logger.Info("Getting syscalls map")
	syscalls, err := module.GetMap("syscalls")
	if err != nil {
		return errors.Wrap(err, "get syscalls map")
	}

	b.logger.Info("Getting PIDs map")
	pids, err := module.GetMap("pids")
	if err != nil {
		return errors.Wrap(err, "get PIDs map")
	}

	b.logger.Info("Getting comms map")
	comms, err := module.GetMap("comms")
	if err != nil {
		return errors.Wrap(err, "get comms map")
	}

	events := make(chan []byte)
	ringbuffer, err := module.InitRingBuf("events", events)
	if err != nil {
		return errors.Wrap(err, "init events ringbuffer")
	}
	ringbuffer.Start()

	b.syscalls = syscalls
	b.pids = pids
	b.comms = comms
	go b.processEvents(events)

	b.logger.Info("Module successfully loaded, watching for events")
	return nil
}

func (b *BpfRecorder) findBtfPath() (string, error) {
	// Use the system btf if possible
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		b.logger.Info("Using system btf file")
		return "", nil
	}

	b.logger.Info("Trying to find matching in-memory btf")

	btf := types.Btf{}
	if err := json.Unmarshal([]byte(btfJSON), &btf); err != nil {
		return "", errors.Wrap(err, "unmarshal btf JSON")
	}

	res, err := osrelease.Read()
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
	syscall.Uname(&uname)

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

	file, err := ioutil.TempFile(
		"",
		fmt.Sprintf("spo-btf-%s-%s-%s-%s", osID, osVersion, arch, kernel),
	)
	if err != nil {
		return "", errors.Wrap(err, "create temp file")
	}
	defer file.Close()

	if _, err := file.Write(btfBytes); err != nil {
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
		pid := binary.LittleEndian.Uint32(event)

		containerID, err := util.ContainerIDForPID(b.containerIDCache, int(pid))
		if err != nil {
			continue
		}

		b.logger.V(4).Info(
			"Found container for PID", "pid", pid, "containerID", containerID,
		)
		if err := b.findContainerID(containerID); err != nil {
			b.logger.Error(err, "unable to find container ID in cluster")
			continue
		}

		if profile, exist := b.profileForContainerIDs.LoadAndDelete(containerID); exist {
			rawComm, err := b.comms.GetValue(unsafe.Pointer(&pid))
			if err != nil {
				b.logger.Error(err, "unable to get command name for PID", "pid", pid)
			}
			comm := toStringByte(rawComm)
			b.logger.Info("Saving PID for profile", "pid", pid, "profile", profile, "comm", comm)

			pids, _ := b.pidsForProfiles.LoadOrStore(profile, []Pid{})
			b.pidsForProfiles.Store(profile, append(pids.([]Pid), Pid{id: pid, comm: comm}))
		}
	}
}

func (b *BpfRecorder) findContainerID(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	errContainerIDNotFound := errors.New("container ID not found")
	if err := util.Retry(
		func() (retryErr error) {
			b.logger.V(4).Info("Searching for in-cluster container ID: " + id)

			pods, err := b.clientset.CoreV1().Pods("").List(
				ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + b.nodeName},
			)
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
						b.logger.V(4).Info(
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
	b.syscalls.GetModule().Close()
	b.syscalls = nil
	b.pids = nil
	b.comms = nil
	os.RemoveAll(b.btfPath)
}

func (b *BpfRecorder) mountNamespaceForPID(pid uint32) (uint64, error) {
	ns_value, err := b.pids.GetValue(unsafe.Pointer(&pid))
	if err != nil {
		return 0, errors.Wrapf(err, "no namespace found for PID: %d", pid)
	}

	mntns := binary.LittleEndian.Uint64(ns_value)
	return mntns, nil
}

func (b *BpfRecorder) syscallNameForID(id int) (string, error) {
	// Check the cache first
	key := strconv.Itoa(id)
	if name, err := b.syscallNamesForIDCache.Get(key); !errors.Is(
		err, ttlcache.ErrNotFound,
	) {
		return name.(string), nil
	}

	name, err := seccomp.ScmpSyscall(id).GetName()
	if err != nil {
		return "", errors.Wrapf(err, "get syscall name for ID %d", id)
	}

	if err := b.syscallNamesForIDCache.Set(key, name); err != nil {
		return "", errors.Wrap(err, "update cache")
	}
	return name, nil
}
