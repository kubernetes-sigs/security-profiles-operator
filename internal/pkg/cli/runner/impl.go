//go:build linux

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

package runner

import (
	"log"
	"os"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/tailer"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.linux.txt
//counterfeiter:generate . impl
type impl interface {
	ReadFile(string) ([]byte, error)
	SetupSeccomp(*specs.LinuxSeccomp) (*configs.Seccomp, error)
	CommandRun(*command.Command) (uint32, error)
	CommandWait(*command.Command) error
	TailFile(string, tailer.Config) (*tailer.Tailer, error)
	Lines(*tailer.Tailer) <-chan string
	TailErr(*tailer.Tailer) error
	StopTail(*tailer.Tailer)
	GetName(libseccomp.ScmpSyscall) (string, error)
	Printf(format string, v ...any)
}

func (*defaultImpl) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (*defaultImpl) SetupSeccomp(config *specs.LinuxSeccomp) (*configs.Seccomp, error) {
	return specconv.SetupSeccomp(config)
}

func (*defaultImpl) CommandRun(cmd *command.Command) (uint32, error) {
	return cmd.Run()
}

func (*defaultImpl) CommandWait(cmd *command.Command) error {
	return cmd.Wait()
}

func (*defaultImpl) TailFile(filename string, config tailer.Config) (*tailer.Tailer, error) {
	return tailer.Follow(filename, config)
}

func (*defaultImpl) Lines(tailFile *tailer.Tailer) <-chan string {
	return tailFile.Lines()
}

func (*defaultImpl) TailErr(tailFile *tailer.Tailer) error {
	return tailFile.Err()
}

func (*defaultImpl) StopTail(tailFile *tailer.Tailer) {
	tailFile.Stop()
}

func (*defaultImpl) GetName(s libseccomp.ScmpSyscall) (string, error) {
	return s.GetName()
}

func (*defaultImpl) Printf(format string, v ...any) {
	log.Printf(format, v...)
}
