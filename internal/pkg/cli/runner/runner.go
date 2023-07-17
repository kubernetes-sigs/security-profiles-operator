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
	"fmt"
	"io"
	"log"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/nxadm/tail"
	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// Runner is the main structure of this package.
type Runner struct {
	impl
	options *Options
}

// New returns a new Runner instance.
func New(options *Options) *Runner {
	return &Runner{
		impl:    &defaultImpl{},
		options: options,
	}
}

// pid is the process ID used for enricher filtering.
var pid uint32

// Run the Runner.
func (r *Runner) Run() error {
	log.Printf("Reading file %s", r.options.profile)
	content, err := r.ReadFile(r.options.profile)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}

	if filepath.Ext(r.options.profile) != seccompprofileapi.ExtJSON {
		log.Print("Assuming YAML profile")
		seccompProfile := &seccompprofileapi.SeccompProfile{}
		if err := r.YamlUnmarshal(content, seccompProfile); err != nil {
			return fmt.Errorf("unmarshal YAML profile: %w", err)
		}

		content, err = r.JSONMarshal(seccompProfile.Spec)
		if err != nil {
			return fmt.Errorf("remarshal JSON profile: %w", err)
		}
	}

	runtimeSpecConfig := &specs.LinuxSeccomp{}
	if err := r.JSONUnmarshal(content, runtimeSpecConfig); err != nil {
		return fmt.Errorf("unmarshal JSON profile: %w", err)
	}

	go r.startEnricher()

	log.Print("Setting up seccomp")
	libConfig, err := r.SetupSeccomp(runtimeSpecConfig)
	if err != nil {
		return fmt.Errorf("convert profile: %w", err)
	}

	log.Print("Load seccomp profile")
	if _, err := r.InitSeccomp(libConfig); err != nil {
		return fmt.Errorf("init profile: %w", err)
	}

	cmd := command.New(r.options.commandOptions)
	newPid, err := r.CommandRun(cmd)
	if err != nil {
		return fmt.Errorf("run command: %w", err)
	}
	atomic.StoreUint32(&pid, newPid)

	if err := r.CommandWait(cmd); err != nil {
		return fmt.Errorf("wait for command: %w", err)
	}

	// Wait for the late syscalls from the audit logs.
	time.Sleep(time.Second)

	return nil
}

func (r *Runner) startEnricher() {
	log.Print("Starting audit log enricher")
	filePath := enricher.LogFilePath()

	tailFile, err := r.TailFile(
		filePath,
		tail.Config{
			ReOpen: true,
			Follow: true,
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekEnd,
			},
		},
	)
	if err != nil {
		log.Printf("Unable to tail file: %v", err)
		return
	}

	log.Printf("Enricher reading from file %s", filePath)
	for l := range r.Lines(tailFile) {
		if l.Err != nil {
			log.Printf("Enricher failed to tail: %v", l.Err)
			break
		}

		line := l.Text
		if !r.IsAuditLine(line) {
			continue
		}

		auditLine, err := r.ExtractAuditLine(line)
		if err != nil {
			log.Printf("Unable to extract audit line: %v", err)
			continue
		}

		currentPid := r.PidLoad()
		if currentPid != 0 && auditLine.ProcessID == int(currentPid) {
			r.printAuditLine(auditLine)
		}
	}
}

func (r *Runner) printAuditLine(line *types.AuditLine) {
	switch line.AuditType {
	case types.AuditTypeSelinux:
		r.printSelinuxLine(line)
	case types.AuditTypeSeccomp:
		r.printSeccompLine(line)
	case types.AuditTypeApparmor:
		r.printApparmorLine(line)
	}
}

func (r *Runner) printSelinuxLine(line *types.AuditLine) {
	log.Printf(
		"SELinux: perm: %s, scontext: %s, tcontext: %s, tclass: %s",
		line.Perm, line.Scontext, line.Tcontext, line.Tclass,
	)
}

func (r *Runner) printSeccompLine(line *types.AuditLine) {
	syscallName, err := r.GetName(libseccomp.ScmpSyscall(line.SystemCallID))
	if err != nil {
		log.Printf("Unable to get syscall name for id %d: %v", line.SystemCallID, err)
		return
	}

	log.Printf("Seccomp: %s (%d)", syscallName, line.SystemCallID)
}

func (r *Runner) printApparmorLine(line *types.AuditLine) {
	log.Printf(
		"AppArmor: %s, operation: %s, profile: %s, name: %s, extra: %s",
		line.Apparmor, line.Operation, line.Profile, line.Name, line.ExtraInfo,
	)
}
