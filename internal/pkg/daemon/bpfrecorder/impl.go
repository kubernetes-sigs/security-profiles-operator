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
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/ReneKroon/ttlcache/v2"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/cobaugh/osrelease"
	seccomp "github.com/seccomp/libseccomp-golang"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	SetTTL(ttlcache.SimpleCache, time.Duration) error
	Getenv(string) string
	InClusterConfig() (*rest.Config, error)
	NewForConfig(*rest.Config) (*kubernetes.Clientset, error)
	Listen(string, string) (net.Listener, error)
	Serve(*grpc.Server, net.Listener) error
	NewModuleFromBufferArgs(*bpf.NewModuleArgs) (*bpf.Module, error)
	BPFLoadObject(*bpf.Module) error
	GetProgram(*bpf.Module, string) (*bpf.BPFProg, error)
	AttachTracepoint(*bpf.BPFProg, string, string) (*bpf.BPFLink, error)
	GetMap(*bpf.Module, string) (*bpf.BPFMap, error)
	InitRingBuf(*bpf.Module, string, chan []byte) (*bpf.RingBuffer, error)
	Stat(string) (os.FileInfo, error)
	Unmarshal([]byte, interface{}) error
	ReadOSRelease() (map[string]string, error)
	Uname(*syscall.Utsname) error
	TempFile(string, string) (*os.File, error)
	Write(*os.File, []byte) (int, error)
	ContainerIDForPID(ttlcache.SimpleCache, int) (string, error)
	GetValue(*bpf.BPFMap, uint32) ([]byte, error)
	DeleteKey(*bpf.BPFMap, uint32) error
	ListPods(context.Context, *kubernetes.Clientset, string) (*v1.PodList, error)
	GetName(seccomp.ScmpSyscall) (string, error)
	RemoveAll(string) error
	Chown(string, int, int) error
	CloseModule(*bpf.BPFMap)
	StartRingBuffer(*bpf.RingBuffer)
	GoArch() string
}

func (d *defaultImpl) SetTTL(cache ttlcache.SimpleCache, ttl time.Duration) error {
	return cache.SetTTL(ttl)
}

func (d *defaultImpl) Getenv(key string) string {
	return os.Getenv(key)
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

func (d *defaultImpl) BPFLoadObject(module *bpf.Module) error {
	return module.BPFLoadObject()
}

func (d *defaultImpl) GetProgram(module *bpf.Module, progName string) (*bpf.BPFProg, error) {
	return module.GetProgram(progName)
}

func (d *defaultImpl) AttachTracepoint(prog *bpf.BPFProg, category, name string) (*bpf.BPFLink, error) {
	return prog.AttachTracepoint(category, name)
}

func (d *defaultImpl) GetMap(module *bpf.Module, mapName string) (*bpf.BPFMap, error) {
	return module.GetMap(mapName)
}

func (d *defaultImpl) InitRingBuf(module *bpf.Module, mapName string, eventsChan chan []byte) (*bpf.RingBuffer, error) {
	return module.InitRingBuf(mapName, eventsChan)
}

func (d *defaultImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (d *defaultImpl) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (d *defaultImpl) ReadOSRelease() (map[string]string, error) {
	return osrelease.Read()
}

func (d *defaultImpl) Uname(buf *syscall.Utsname) error {
	return syscall.Uname(buf)
}

func (d *defaultImpl) TempFile(dir, pattern string) (*os.File, error) {
	return ioutil.TempFile(dir, pattern)
}

func (d *defaultImpl) Write(file *os.File, b []byte) (n int, err error) {
	return file.Write(b)
}

func (d *defaultImpl) ContainerIDForPID(cache ttlcache.SimpleCache, pid int) (string, error) {
	return util.ContainerIDForPID(cache, pid)
}

func (d *defaultImpl) GetValue(m *bpf.BPFMap, key uint32) ([]byte, error) {
	return m.GetValue(unsafe.Pointer(&key))
}

func (d *defaultImpl) DeleteKey(m *bpf.BPFMap, key uint32) error {
	return m.DeleteKey(unsafe.Pointer(&key))
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

func (d *defaultImpl) GoArch() string {
	return runtime.GOARCH
}

func (d *defaultImpl) StartRingBuffer(b *bpf.RingBuffer) {
	b.Start()
}

func (d *defaultImpl) CloseModule(m *bpf.BPFMap) {
	m.GetModule().Close()
}
