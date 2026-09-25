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
	"context"
	"errors"
	"net"
	"os"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/jellydator/ttlcache/v3"
	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	apimetrics "sigs.k8s.io/security-profiles-operator/api/grpc/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.bpf.txt
//counterfeiter:generate . impl
type impl interface {
	InClusterConfig() (*rest.Config, error)
	NewForConfig(*rest.Config) (*kubernetes.Clientset, error)
	Listen(string, string) (net.Listener, error)
	Serve(*grpc.Server, net.Listener) error
	NewModuleFromBufferArgs(*bpf.NewModuleArgs) (*bpf.Module, error)
	BPFMapIterator(*bpf.BPFMap) *bpf.BPFMapIterator
	BPFMapIteratorNext(*bpf.BPFMapIterator) bool
	BPFLoadObject(*bpf.Module) error
	GetProgram(*bpf.Module, string) (*bpf.BPFProg, error)
	AttachGeneric(*bpf.BPFProg) (*bpf.BPFLink, error)
	GetMap(*bpf.Module, string) (*bpf.BPFMap, error)
	InitRingBuf(*bpf.Module, string, chan []byte) (*bpf.RingBuffer, error)
	Stat(string) (os.FileInfo, error)
	ContainerIDForPID(*ttlcache.Cache[string, string], int) (string, error)
	GetValue(*bpf.BPFMap, uint32) ([]byte, error)
	UpdateValue(*bpf.BPFMap, uint32, []byte) error
	DeleteKey(*bpf.BPFMap, uint32) error
	GetValue64(*bpf.BPFMap, uint64) ([]byte, error)
	UpdateValue64(*bpf.BPFMap, uint64, []byte) error
	DeleteKey64(*bpf.BPFMap, uint64) error
	IsCgroupV2() bool
	ListPods(context.Context, *kubernetes.Clientset, string) (*v1.PodList, error)
	GetName(seccomp.ScmpSyscall) (string, error)
	RemoveAll(string) error
	Chown(string, int, int) error
	PollRingBuffer(*bpf.RingBuffer, int)
	Readlink(string) (string, error)
	DialMetrics() (*grpc.ClientConn, error)
	BpfIncClient(client apimetrics.MetricsClient) (apimetrics.Metrics_BpfIncClient, error)
	CloseGRPC(*grpc.ClientConn) error
	SendMetric(apimetrics.Metrics_BpfIncClient, *apimetrics.BpfRequest) error
	InitGlobalVariable(*bpf.Module, string, any) error
}

func (d *defaultImpl) InClusterConfig() (*rest.Config, error) {
	return rest.InClusterConfig()
}

func (d *defaultImpl) NewForConfig(
	c *rest.Config,
) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(c)
}

func (d *defaultImpl) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (d *defaultImpl) Serve(grpcServer *grpc.Server, listener net.Listener) error {
	return grpcServer.Serve(listener)
}

func (d *defaultImpl) NewModuleFromBufferArgs(args *bpf.NewModuleArgs) (*bpf.Module, error) {
	return bpf.NewModuleFromBufferArgs(*args)
}

func (*defaultImpl) BPFMapIterator(m *bpf.BPFMap) *bpf.BPFMapIterator {
	return m.Iterator()
}

func (*defaultImpl) BPFMapIteratorNext(it *bpf.BPFMapIterator) bool {
	return it.Next()
}

func (d *defaultImpl) BPFLoadObject(module *bpf.Module) error {
	return module.BPFLoadObject()
}

func (d *defaultImpl) GetProgram(module *bpf.Module, progName string) (*bpf.BPFProg, error) {
	return module.GetProgram(progName)
}

func (d *defaultImpl) AttachGeneric(prog *bpf.BPFProg) (*bpf.BPFLink, error) {
	return prog.AttachGeneric()
}

func (d *defaultImpl) GetMap(module *bpf.Module, mapName string) (*bpf.BPFMap, error) {
	return module.GetMap(mapName)
}

func (d *defaultImpl) InitRingBuf(
	module *bpf.Module,
	mapName string,
	eventsChan chan []byte,
) (*bpf.RingBuffer, error) {
	return module.InitRingBuf(mapName, eventsChan)
}

func (d *defaultImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (d *defaultImpl) ContainerIDForPID(
	cache *ttlcache.Cache[string, string],
	pid int,
) (string, error) {
	return util.ContainerIDForPID(cache, pid)
}

func (d *defaultImpl) GetValue(m *bpf.BPFMap, key uint32) ([]byte, error) {
	if m == nil {
		return nil, errors.New("provided bpf map is nil")
	}

	return m.GetValue(unsafe.Pointer(&key))
}

func (d *defaultImpl) UpdateValue(m *bpf.BPFMap, key uint32, value []byte) error {
	if m == nil {
		return errors.New("provided bpf map is nil")
	}

	return m.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
}

func (d *defaultImpl) DeleteKey(m *bpf.BPFMap, key uint32) error {
	if m == nil {
		return errors.New("provided bpf map is nil")
	}

	return m.DeleteKey(unsafe.Pointer(&key))
}

func (d *defaultImpl) GetValue64(m *bpf.BPFMap, key uint64) ([]byte, error) {
	if m == nil {
		return nil, errors.New("provided bpf map is nil")
	}

	return m.GetValue(unsafe.Pointer(&key))
}

func (d *defaultImpl) UpdateValue64(m *bpf.BPFMap, key uint64, value []byte) error {
	if m == nil {
		return errors.New("provided bpf map is nil")
	}

	return m.Update(unsafe.Pointer(&key), unsafe.Pointer(&value[0]))
}

func (d *defaultImpl) DeleteKey64(m *bpf.BPFMap, key uint64) error {
	if m == nil {
		return errors.New("provided bpf map is nil")
	}

	return m.DeleteKey(unsafe.Pointer(&key))
}

// IsCgroupV2 reports whether the host runs the unified cgroup hierarchy only.
// On hybrid or legacy hosts the cgroup ID seen by BPF does not identify a
// container.
func (d *defaultImpl) IsCgroupV2() bool {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil {
		return false
	}

	return st.Type == unix.CGROUP2_SUPER_MAGIC
}

func (d *defaultImpl) ListPods(
	ctx context.Context, c *kubernetes.Clientset, nodeName string,
) (*v1.PodList, error) {
	return c.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
}

func (d *defaultImpl) GetName(s seccomp.ScmpSyscall) (string, error) {
	return s.GetName()
}

func (d *defaultImpl) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (d *defaultImpl) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

func (d *defaultImpl) PollRingBuffer(b *bpf.RingBuffer, timeout int) {
	b.Poll(timeout)
}

func (d *defaultImpl) Readlink(name string) (string, error) {
	return os.Readlink(name)
}

func (d *defaultImpl) DialMetrics() (*grpc.ClientConn, error) {
	return metrics.Dial()
}

func (d *defaultImpl) BpfIncClient(
	client apimetrics.MetricsClient,
) (apimetrics.Metrics_BpfIncClient, error) {
	return client.BpfInc(context.Background())
}

func (d *defaultImpl) CloseGRPC(conn *grpc.ClientConn) error {
	return conn.Close()
}

func (d *defaultImpl) SendMetric(
	client apimetrics.Metrics_BpfIncClient,
	in *apimetrics.BpfRequest,
) error {
	return client.Send(in)
}

func (d *defaultImpl) InitGlobalVariable(module *bpf.Module, name string, value any) error {
	return module.InitGlobalVariable(name, value)
}
