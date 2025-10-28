//go:build linux
// +build linux

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

package runner

import (
	"encoding/json"
	"log"
	"os"
	"sync/atomic"

	"github.com/nxadm/tail"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"sigs.k8s.io/yaml"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.linux.txt
//counterfeiter:generate . impl
type impl interface {
	ReadFile(string) ([]byte, error)
	YamlUnmarshal([]byte, interface{}) error
	JSONMarshal(any) ([]byte, error)
	JSONUnmarshal([]byte, any) error
	SetupSeccomp(*specs.LinuxSeccomp) (*configs.Seccomp, error)
	InitSeccomp(*configs.Seccomp) (int, error)
	CommandRun(*command.Command) (uint32, error)
	CommandWait(*command.Command) error
	TailFile(string, tail.Config) (*tail.Tail, error)
	Lines(*tail.Tail) chan *tail.Line
	IsAuditLine(string) bool
	ExtractAuditLine(string) (*types.AuditLine, error)
	GetName(libseccomp.ScmpSyscall) (string, error)
	PidLoad() uint32
	Printf(format string, v ...any)
}

func (*defaultImpl) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (*defaultImpl) YamlUnmarshal(y []byte, o interface{}) error {
	return yaml.Unmarshal(y, o)
}

func (*defaultImpl) JSONMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (*defaultImpl) JSONUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (*defaultImpl) SetupSeccomp(config *specs.LinuxSeccomp) (*configs.Seccomp, error) {
	return specconv.SetupSeccomp(config)
}

func (*defaultImpl) InitSeccomp(config *configs.Seccomp) (int, error) {
	return seccomp.InitSeccomp(config)
}

func (*defaultImpl) CommandRun(cmd *command.Command) (uint32, error) {
	return cmd.Run()
}

func (*defaultImpl) CommandWait(cmd *command.Command) error {
	return cmd.Wait()
}

func (*defaultImpl) TailFile(filename string, config tail.Config) (*tail.Tail, error) {
	return tail.TailFile(filename, config)
}

func (*defaultImpl) Lines(tailFile *tail.Tail) chan *tail.Line {
	return tailFile.Lines
}

func (*defaultImpl) IsAuditLine(line string) bool {
	return auditsource.IsAuditLine(line)
}

func (*defaultImpl) ExtractAuditLine(line string) (*types.AuditLine, error) {
	return auditsource.ExtractAuditLine(line)
}

func (*defaultImpl) GetName(s libseccomp.ScmpSyscall) (string, error) {
	return s.GetName()
}

func (*defaultImpl) PidLoad() uint32 {
	return atomic.LoadUint32(&pid)
}

func (*defaultImpl) Printf(format string, v ...any) {
	log.Printf(format, v...)
}
