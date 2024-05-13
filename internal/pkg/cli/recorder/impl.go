//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2023 The Kubernetes Authors.

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

package recorder

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
	"github.com/containers/common/pkg/seccomp"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/printers"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.bpf.txt
//counterfeiter:generate . impl
type impl interface {
	LoadBpfRecorder(*bpfrecorder.BpfRecorder) error
	UnloadBpfRecorder(*bpfrecorder.BpfRecorder)
	CommandRun(*command.Command) (uint32, error)
	CommandWait(*command.Command) error
	WaitForPidExit(*bpfrecorder.BpfRecorder, context.Context, uint32) error
	FindProcMountNamespace(*bpfrecorder.BpfRecorder, uint32) (uint32, error)
	SyscallsIterator(*bpfrecorder.BpfRecorder) *libbpfgo.BPFMapIterator
	IteratorNext(*libbpfgo.BPFMapIterator) bool
	IteratorKey(*libbpfgo.BPFMapIterator) []byte
	SyscallsGetValue(*bpfrecorder.BpfRecorder, uint32) ([]byte, error)
	GetName(libseccomp.ScmpSyscall) (string, error)
	MarshalIndent(any, string, string) ([]byte, error)
	Create(string) (io.WriteCloser, error)
	PrintObj(printers.YAMLPrinter, runtime.Object, io.Writer) error
	GoArchToSeccompArch(string) (seccomp.Arch, error)
	Notify(chan<- os.Signal, ...os.Signal)
}

func (*defaultImpl) LoadBpfRecorder(b *bpfrecorder.BpfRecorder) error {
	return b.Load(true)
}

func (*defaultImpl) UnloadBpfRecorder(b *bpfrecorder.BpfRecorder) {
	b.Unload()
}

func (*defaultImpl) CommandRun(cmd *command.Command) (uint32, error) {
	return cmd.Run()
}

func (*defaultImpl) FindProcMountNamespace(b *bpfrecorder.BpfRecorder, pid uint32) (uint32, error) {
	return b.FindProcMountNamespace(pid)
}

func (*defaultImpl) CommandWait(cmd *command.Command) error {
	return cmd.Wait()
}

func (*defaultImpl) WaitForPidExit(b *bpfrecorder.BpfRecorder, ctx context.Context, pid uint32) error {
	return b.WaitForPidExit(ctx, pid)
}

func (*defaultImpl) SyscallsIterator(b *bpfrecorder.BpfRecorder) *libbpfgo.BPFMapIterator {
	return b.Syscalls().Iterator()
}

func (*defaultImpl) IteratorNext(it *libbpfgo.BPFMapIterator) bool {
	return it.Next()
}

func (*defaultImpl) IteratorKey(it *libbpfgo.BPFMapIterator) []byte {
	return it.Key()
}

func (*defaultImpl) SyscallsGetValue(b *bpfrecorder.BpfRecorder, mntns uint32) ([]byte, error) {
	return b.Syscalls().GetValue(unsafe.Pointer(&mntns))
}

func (*defaultImpl) GetName(s libseccomp.ScmpSyscall) (string, error) {
	return s.GetName()
}

func (*defaultImpl) MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}

func (*defaultImpl) Create(name string) (io.WriteCloser, error) {
	return os.Create(name)
}

func (*defaultImpl) PrintObj(p printers.YAMLPrinter, obj runtime.Object, w io.Writer) error {
	return p.PrintObj(obj, w)
}

func (*defaultImpl) GoArchToSeccompArch(arch string) (seccomp.Arch, error) {
	return seccomp.GoArchToSeccompArch(arch)
}

func (*defaultImpl) Notify(c chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(c, sig...)
}
