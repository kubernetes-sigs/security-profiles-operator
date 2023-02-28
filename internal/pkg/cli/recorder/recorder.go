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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"unsafe"

	"github.com/containers/common/pkg/seccomp"
	"github.com/go-logr/logr"
	libseccomp "github.com/seccomp/libseccomp-golang"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
)

// Recorder is the main structure of this package.
type Recorder struct {
	options     *Options
	bpfRecorder *bpfrecorder.BpfRecorder
}

// New returns a new Recorder instance.
func New(options *Options) *Recorder {
	return &Recorder{options: options}
}

// Run the Recorder.
func (r *Recorder) Run() error {
	r.bpfRecorder = bpfrecorder.New(logr.New(&LogSink{}))
	if err := r.bpfRecorder.Load(false); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer r.bpfRecorder.Unload()

	//nolint:gosec // passing the args is intentional here
	cmd := exec.Command(r.options.command, r.options.args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}

	// Allow to interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Printf("Got interrupted, terminating process")

		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			log.Printf("Unable to terminate process: %v", err)
		}
	}()

	pid := uint32(cmd.Process.Pid)
	log.Printf("Running command with PID: %d", pid)

	if err := cmd.Wait(); err != nil {
		log.Printf("Command not exited successfully: %v", err)
	}

	if err := r.processData(pid); err != nil {
		return fmt.Errorf("build profile: %w", err)
	}

	return nil
}

func (r *Recorder) processData(pid uint32) error {
	log.Printf("Processing recorded data")

	iterator := r.bpfRecorder.Syscalls().Iterator()
	for iterator.Next() {
		currentPid := binary.LittleEndian.Uint32(iterator.Key())

		if currentPid != pid {
			continue
		}
		log.Print("Found PID in bpf map")

		syscallsValue, err := r.bpfRecorder.Syscalls().GetValue(unsafe.Pointer(&currentPid))
		if err != nil {
			return fmt.Errorf("get syscalls from pids map: %w", err)
		}

		syscalls := []string{}
		for id, found := range syscallsValue {
			if found != 0 {
				name, err := libseccomp.ScmpSyscall(id).GetName()
				if err != nil {
					return fmt.Errorf("get syscall name for id %d: %w", id, err)
				}

				syscalls = append(syscalls, name)
			}
		}

		log.Printf("Got syscalls: %s", strings.Join(syscalls, ", "))
		if err := r.buildProfile(syscalls); err != nil {
			return fmt.Errorf("build profile: %w", err)
		}

		return nil
	}

	return fmt.Errorf("find PID %d in bpf data map", pid)
}

func (r *Recorder) buildProfile(names []string) error {
	arch, err := r.goArchToSeccompArch(runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("get seccomp arch: %w", err)
	}

	spec := seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccomp.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []*seccompprofileapi.Syscall{{
			Action: seccomp.ActAllow,
			Names:  names,
		}},
	}

	defer func() {
		log.Printf("Wrote seccomp profile to: %s", r.options.outputFile)
	}()

	if r.options.typ == TypeRawSeccomp {
		return r.buildProfileRaw(&spec)
	}

	return r.buildProfileCRD(&spec)
}

func (r *Recorder) buildProfileRaw(spec *seccompprofileapi.SeccompProfileSpec) error {
	if r.options.outputFile == DefaultOutputFile {
		r.options.outputFile = strings.ReplaceAll(r.options.outputFile, ".yaml", ".json")
	}

	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON profile: %w", err)
	}

	const defaultMode os.FileMode = 0o644
	if err := os.WriteFile(r.options.outputFile, data, defaultMode); err != nil {
		return fmt.Errorf("write JSON file: %w", err)
	}

	return nil
}

func (r *Recorder) buildProfileCRD(spec *seccompprofileapi.SeccompProfileSpec) error {
	profile := &seccompprofileapi.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SeccompProfile",
			APIVersion: seccompprofileapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: r.options.command,
		},
		Spec: *spec,
	}

	file, err := os.Create(r.options.outputFile)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	printer := printers.YAMLPrinter{}
	if err := printer.PrintObj(profile, file); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	return nil
}

func (r *Recorder) goArchToSeccompArch(goarch string) (seccompprofileapi.Arch, error) {
	seccompArch, err := seccomp.GoArchToSeccompArch(goarch)
	if err != nil {
		return "", fmt.Errorf("convert golang to seccomp arch: %w", err)
	}
	return seccompprofileapi.Arch(seccompArch), nil
}
