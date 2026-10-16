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
	// descendants are the start times of the processes the enricher found
	// to be descendants of the command, by process ID. It is only used by
	// the enricher.
	descendants map[int]uint64
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

		spec, crdErr := specFromCRD(content)

		switch {
		case errors.Is(crdErr, artifact.ErrNoKind) && json.Valid(content):
			// A raw profile under another name, like the one spoc pull
			// saves for a runtime format artifact with --output-file.
			log.Print("Profile has no kind, using it as JSON profile")
		case crdErr != nil:
			return crdErr
		default:
			content = spec
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

	// The audit log gets followed from its end before the command starts,
	// so that none of its lines are missed.
	tail := r.followAuditLog()

	r.options.commandOptions.PreStart = confine(runtimeSpecConfig)
	cmd := command.New(r.options.commandOptions)

	newPid, err := r.CommandRun(cmd)
	if err != nil {
		r.stopAuditLog(tail)

		return fmt.Errorf("run command: %w", err)
	}

	// The lines get read once the process ID is known, the tailer keeps
	// them until then.
	r.pid.Store(newPid)

	var enriched chan struct{}

	if tail != nil {
		enriched = make(chan struct{})

		go func() {
			defer close(enriched)

			r.enrich(tail)
		}()
	}

	waitErr := r.CommandWait(cmd)

	if tail != nil {
		// Wait for the late syscalls from the audit logs, which matter most
		// if the command failed.
		time.Sleep(r.enricherGracePeriod)
	}

	// Release the audit log, which ends the enricher, and wait for the lines
	// it still has to print.
	r.stopAuditLog(tail)

	if enriched != nil {
		<-enriched
	}

	if waitErr != nil {
		return fmt.Errorf("wait for command: %w", waitErr)
	}

	return nil
}

// specFromCRD returns the spec of a SeccompProfile CRD as runtime-spec JSON.
func specFromCRD(content []byte) ([]byte, error) {
	profile, err := artifact.ReadSingleProfile(content)
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

// followAuditLog starts following the audit log at its end. It returns nil
// if the audit log cannot be followed, for example without root.
func (r *Runner) followAuditLog() *tailer.Tailer {
	log.Print("Starting audit log enricher")

	filePath := common.LogFilePath()

	tail, err := r.TailFile(filePath, tailer.Config{})
	if err != nil {
		log.Printf("Unable to tail file: %v", err)

		return nil
	}

	log.Printf("Enricher reading from file %s", filePath)

	return tail
}

// stopAuditLog stops following the audit log, if it gets followed.
func (r *Runner) stopAuditLog(tail *tailer.Tailer) {
	if tail != nil {
		r.StopTail(tail)
	}
}

// enrich prints the audit lines of the command and its descendants, which
// inherit the profile, until the tailer stops.
func (r *Runner) enrich(tail *tailer.Tailer) {
	for line := range r.Lines(tail) {
		auditLine, err := auditsource.ExtractAuditLine(line)
		if err != nil {
			// Not an audit line spoc understands.
			continue
		}

		if r.isCommandProcess(auditLine.ProcessID) {
			r.printAuditLine(auditLine)
		}
	}

	if err := r.TailErr(tail); err != nil {
		log.Printf("Enricher failed to tail: %v", err)
	}
}

// maxProcessDepth bounds the walk up the process tree, which could otherwise
// loop if process IDs get reused while walking.
const maxProcessDepth = 64

// isCommandProcess reports whether the process is the command or one of its
// descendants. A descendant which exited before its audit line got read
// cannot be told apart from any other process, unless it was seen before.
// The descendants seen are known by their start time as well, so that a
// later process with the same process ID does not count as one.
func (r *Runner) isCommandProcess(pid int) bool {
	commandPid := int(r.pid.Load())
	if commandPid == 0 || pid <= 1 {
		return false
	}

	if pid == commandPid {
		return true
	}

	parent, startTime, err := r.ProcessInfo(pid)
	if err != nil {
		// The audit line is the one of the last process with the process
		// ID, which is gone now.
		_, known := r.descendants[pid]

		return known
	}

	current, currentStartTime := pid, startTime

	for range maxProcessDepth {
		start, known := r.descendants[current]
		if (known && start == currentStartTime) || parent == commandPid {
			if r.descendants == nil {
				r.descendants = map[int]uint64{}
			}

			r.descendants[pid] = startTime

			return true
		}

		if parent <= 1 {
			break
		}

		current = parent

		if parent, currentStartTime, err = r.ProcessInfo(current); err != nil {
			break
		}
	}

	// A process seen before with the same process ID has exited.
	delete(r.descendants, pid)

	return false
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
