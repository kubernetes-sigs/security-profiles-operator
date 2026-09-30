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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	libseccomp "github.com/seccomp/libseccomp-golang"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/tailer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// ErrBaseProfile is returned for profiles referencing a base profile, which
// spoc run cannot resolve.
var ErrBaseProfile = errors.New(
	"base profiles are not supported, merge the base profile into the profile first",
)

// Runner is the main structure of this package.
type Runner struct {
	impl
	options *Options
	// pid is the process ID used for enricher filtering.
	pid atomic.Uint32
	// enricherGracePeriod is how long to wait for audit logs after the
	// command exited.
	enricherGracePeriod time.Duration
}

// New returns a new Runner instance.
func New(options *Options) *Runner {
	return &Runner{
		impl:                &defaultImpl{},
		options:             options,
		enricherGracePeriod: time.Second,
	}
}

// Run the Runner.
func (r *Runner) Run() error {
	log.Printf("Reading file %s", r.options.profile)

	content, err := r.ReadFile(r.options.profile)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}

	if filepath.Ext(r.options.profile) != seccompprofileapi.ExtJSON {
		log.Print("Assuming YAML profile")

		content, err = specFromCRD(content)
		if err != nil {
			return err
		}
	}

	runtimeSpecConfig := &specs.LinuxSeccomp{}
	if err := json.Unmarshal(content, runtimeSpecConfig); err != nil {
		return fmt.Errorf("unmarshal JSON profile: %w", err)
	}

	// The profile gets loaded by the run helper, check it before starting
	// anything.
	log.Print("Setting up seccomp")

	if _, err := r.SetupSeccomp(runtimeSpecConfig); err != nil {
		return fmt.Errorf("convert profile: %w", err)
	}

	go r.startEnricher()

	r.options.commandOptions.PreStart = confine(runtimeSpecConfig)
	cmd := command.New(r.options.commandOptions)

	newPid, err := r.CommandRun(cmd)
	if err != nil {
		return fmt.Errorf("run command: %w", err)
	}

	r.pid.Store(newPid)

	waitErr := r.CommandWait(cmd)

	// Wait for the late syscalls from the audit logs, which matter most if
	// the command failed.
	time.Sleep(r.enricherGracePeriod)

	if waitErr != nil {
		return fmt.Errorf("wait for command: %w", waitErr)
	}

	return nil
}

// specFromCRD returns the spec of a SeccompProfile CRD as runtime-spec JSON.
func specFromCRD(content []byte) ([]byte, error) {
	profile, err := artifact.ReadProfile(content)
	if err != nil {
		return nil, fmt.Errorf("unmarshal YAML profile: %w", err)
	}

	seccompProfile, ok := profile.(*seccompprofileapi.SeccompProfile)
	if !ok {
		return nil, fmt.Errorf(
			"unmarshal YAML profile: expected a SeccompProfile, got %s",
			profile.GetObjectKind().GroupVersionKind().Kind,
		)
	}

	if name := seccompProfile.Spec.BaseProfileName; name != "" {
		return nil, fmt.Errorf("profile references base profile %q: %w", name, ErrBaseProfile)
	}

	content, err = json.Marshal(seccompProfile.Spec)
	if err != nil {
		return nil, fmt.Errorf("remarshal JSON profile: %w", err)
	}

	return content, nil
}

func (r *Runner) startEnricher() {
	log.Print("Starting audit log enricher")

	filePath := common.LogFilePath()

	tailFile, err := r.TailFile(filePath, tailer.Config{})
	if err != nil {
		log.Printf("Unable to tail file: %v", err)

		return
	}

	log.Printf("Enricher reading from file %s", filePath)

	for line := range r.Lines(tailFile) {
		auditLine, err := auditsource.ExtractAuditLine(line)
		if err != nil {
			// Not an audit line spoc understands.
			continue
		}

		currentPid := r.pid.Load()
		if currentPid != 0 && auditLine.ProcessID == int(currentPid) {
			r.printAuditLine(auditLine)
		}
	}

	if err := r.TailErr(tailFile); err != nil {
		log.Printf("Enricher failed to tail: %v", err)
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
	r.Printf(
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

	r.Printf("Seccomp: %s (%d)", syscallName, line.SystemCallID)
}

func (r *Runner) printApparmorLine(line *types.AuditLine) {
	r.Printf(
		"AppArmor: %s, operation: %s, profile: %s, name: %s, extra: %s",
		line.Apparmor, line.Operation, line.Profile, line.Name, line.ExtraInfo,
	)
}
