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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/go-logr/logr"
	libseccomp "github.com/seccomp/libseccomp-golang"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	waitForPidExitTimeout = 10 * time.Second
	WaitForSigIntMessage  = "Waiting for CTRL+C / SIGINT..."
)

// Recorder is the main structure of this package.
type Recorder struct {
	impl
	options     *Options
	bpfRecorder *bpfrecorder.BpfRecorder
}

// New returns a new Recorder instance.
func New(options *Options) *Recorder {
	return &Recorder{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Recorder.
func (r *Recorder) Run() error {
	recordAppArmor := ((r.options.typ == TypeApparmor) ||
		(r.options.typ == TypeRawAppArmor) ||
		(r.options.typ == TypeAll))
	recordSeccomp := ((r.options.typ == TypeSeccomp) ||
		(r.options.typ == TypeRawSeccomp) ||
		(r.options.typ == TypeAll))

	// https://github.com/kubernetes-sigs/security-profiles-operator/issues/2384
	// Explicitly check for BPF LSM support as the recorder fails silently
	// to support seccomp-only use cases.
	if recordAppArmor && !r.BPFLSMEnabled() {
		return errors.New("BPF LSM is not enabled for this kernel")
	}

	r.bpfRecorder = bpfrecorder.New(
		r.options.commandOptions.Command(),
		logr.New(&cli.LogSink{}),
		recordSeccomp,
		recordAppArmor,
	)

	if err := r.LoadBpfRecorder(r.bpfRecorder); err != nil {
		return fmt.Errorf("load: %w", err)
	}

	if err := r.StartBpfRecording(r.bpfRecorder); err != nil {
		return fmt.Errorf("record: %w", err)
	}
	defer func(r *Recorder, recorder *bpfrecorder.BpfRecorder) {
		err := r.StopBpfRecording(recorder)
		if err != nil {
			log.Println(fmt.Errorf("stop BPF recording: %w", err))
		}
	}(r, r.bpfRecorder)

	var mntns uint32

	if r.options.noProcStart {
		// command execution is managed externally,
		// so we play dumb and just wait for SIGINT.
		ch := make(chan os.Signal, 1)
		r.Notify(ch, os.Interrupt)
		log.Print(WaitForSigIntMessage)
		<-ch
	} else {
		cmd := command.New(r.options.commandOptions)

		pid, err := r.CommandRun(cmd)
		if err != nil {
			return fmt.Errorf("run command: %w", err)
		}

		mntns, err = r.FindProcMountNamespace(r.bpfRecorder, uint32(os.Getpid()))
		if err != nil {
			return fmt.Errorf("finding mntns of PID %d: %w", pid, err)
		}

		if err := r.CommandWait(cmd); err != nil {
			log.Printf("Command did not exit successfully: %v", err)
		}

		log.Println("Waiting for events processor to catch up...")

		ctx, cancel := context.WithTimeout(context.Background(), waitForPidExitTimeout)
		defer cancel()

		if err := r.WaitForPidExit(r.bpfRecorder, ctx, pid); err != nil {
			log.Printf("Did not register exit signal for pid %d: %v", pid, err)
		}
	}

	file, err := r.Create(r.outFile())
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	if recordAppArmor {
		if err := r.processAppArmor(file, mntns); err != nil {
			return fmt.Errorf("build apparmor profile: %w", err)
		}
	}

	if recordSeccomp {
		if err := r.processSeccomp(file, mntns); err != nil {
			return fmt.Errorf("build seccomp profile: %w", err)
		}
	}

	return nil
}

func (r *Recorder) outFile() string {
	outFile := r.options.outputFile
	if outFile == DefaultOutputFile {
		if r.options.typ == TypeRawAppArmor {
			outFile = strings.TrimSuffix(outFile, ".yaml") + ".json"
		}

		if r.options.typ == TypeRawSeccomp {
			outFile = strings.TrimSuffix(outFile, ".yaml") + ".apparmor"
		}
	}

	return outFile
}

func (r *Recorder) processSeccomp(writer io.Writer, mntns uint32) error {
	log.Printf("Processing recorded data")

	// A set of all observed syscalls.
	// We may iterate over multiple mount namespaces if mntns is 0, so we need to remove duplicates
	syscallsMap := map[string]bool{}
	foundMntns := false

	it := r.SyscallsIterator(r.bpfRecorder)
	for r.IteratorNext(it) {
		currentMntns := binary.LittleEndian.Uint32(r.IteratorKey(it))
		if mntns != 0 && currentMntns != mntns {
			continue
		}

		foundMntns = true

		log.Printf("Found process mntns %d in bpf map", currentMntns)

		syscallsValue, err := r.SyscallsGetValue(r.bpfRecorder, currentMntns)
		if err != nil {
			return fmt.Errorf("get syscalls from bpf map: %w", err)
		}

		for id, found := range syscallsValue {
			if found != 0 {
				name, err := r.GetName(libseccomp.ScmpSyscall(id))
				if err != nil {
					return fmt.Errorf("get syscall name for id %d: %w", id, err)
				}

				syscallsMap[name] = true
			}
		}
	}

	if !foundMntns {
		return fmt.Errorf("find mntns %d in bpf data map", mntns)
	}

	// map -> slice
	syscalls := make([]string, len(syscallsMap))
	i := 0

	for k := range syscallsMap {
		syscalls[i] = k
		i++
	}

	log.Printf("Got syscalls: %s", strings.Join(syscalls, ", "))

	if err := r.buildProfile(writer, syscalls); err != nil {
		return fmt.Errorf("build profile: %w", err)
	}

	return nil
}

func (r *Recorder) generateAppArmorProfile(mntns uint32) apparmorprofileapi.AppArmorAbstract {
	processed := r.bpfRecorder.AppArmor.GetAppArmorProcessed(mntns)

	abstract := apparmorprofileapi.AppArmorAbstract{}
	enabled := true

	if len(processed.FileProcessed.AllowedExecutables) != 0 || len(processed.FileProcessed.AllowedLibraries) != 0 {
		abstract.Executable = &apparmorprofileapi.AppArmorExecutablesRules{}

		if len(processed.FileProcessed.AllowedExecutables) != 0 {
			sort.Strings(processed.FileProcessed.AllowedExecutables)
			ExecutableAllowedExecCopy := make([]string, len(processed.FileProcessed.AllowedExecutables))
			copy(ExecutableAllowedExecCopy, processed.FileProcessed.AllowedExecutables)
			abstract.Executable.AllowedExecutables = &ExecutableAllowedExecCopy
		}

		if len(processed.FileProcessed.AllowedLibraries) != 0 {
			sort.Strings(processed.FileProcessed.AllowedLibraries)
			ExecutableAllowedLibCopy := make([]string, len(processed.FileProcessed.AllowedLibraries))
			copy(ExecutableAllowedLibCopy, processed.FileProcessed.AllowedLibraries)
			abstract.Executable.AllowedLibraries = &ExecutableAllowedLibCopy
		}
	}

	if (len(processed.FileProcessed.ReadOnlyPaths) != 0) ||
		(len(processed.FileProcessed.WriteOnlyPaths) != 0) ||
		(len(processed.FileProcessed.ReadWritePaths) != 0) {
		files := apparmorprofileapi.AppArmorFsRules{}

		if len(processed.FileProcessed.ReadOnlyPaths) != 0 {
			sort.Strings(processed.FileProcessed.ReadOnlyPaths)
			FileReadOnlyCopy := make([]string, len(processed.FileProcessed.ReadOnlyPaths))
			copy(FileReadOnlyCopy, processed.FileProcessed.ReadOnlyPaths)
			files.ReadOnlyPaths = &FileReadOnlyCopy
		}

		if len(processed.FileProcessed.WriteOnlyPaths) != 0 {
			sort.Strings(processed.FileProcessed.WriteOnlyPaths)
			FileWriteOnlyCopy := make([]string, len(processed.FileProcessed.WriteOnlyPaths))
			copy(FileWriteOnlyCopy, processed.FileProcessed.WriteOnlyPaths)
			files.WriteOnlyPaths = &FileWriteOnlyCopy
		}

		if len(processed.FileProcessed.ReadWritePaths) != 0 {
			sort.Strings(processed.FileProcessed.ReadWritePaths)
			FileReadWriteCopy := make([]string, len(processed.FileProcessed.ReadWritePaths))
			copy(FileReadWriteCopy, processed.FileProcessed.ReadWritePaths)
			files.ReadWritePaths = &FileReadWriteCopy
		}

		abstract.Filesystem = &files
	}

	if processed.Socket.UseRaw || processed.Socket.UseTCP || processed.Socket.UseUDP {
		net := apparmorprofileapi.AppArmorNetworkRules{}
		proto := apparmorprofileapi.AppArmorAllowedProtocols{}

		if processed.Socket.UseRaw {
			net.AllowRaw = &enabled
		}

		if processed.Socket.UseTCP {
			proto.AllowTCP = &enabled
			net.Protocols = &proto
		}

		if processed.Socket.UseUDP {
			proto.AllowUDP = &enabled
			net.Protocols = &proto
		}

		abstract.Network = &net
	}

	if len(processed.Capabilities) != 0 {
		capabilities := apparmorprofileapi.AppArmorCapabilityRules{}
		capabilities.AllowedCapabilities = processed.Capabilities
		abstract.Capability = &capabilities
	}

	return abstract
}

func (r *Recorder) processAppArmor(writer io.Writer, mntns uint32) error {
	var spec apparmorprofileapi.AppArmorProfileSpec

	if mntns > 0 {
		abstract := r.generateAppArmorProfile(mntns)
		spec = apparmorprofileapi.AppArmorProfileSpec{
			Abstract: abstract,
		}
	} else {
		// Special case of CLI recording with --no-proc: We span all mount namespaces.
		mountNamespaces := r.bpfRecorder.AppArmor.GetKnownMntns()
		parts := make([]client.Object, 0, len(mountNamespaces))

		for _, mntns := range mountNamespaces {
			profile := apparmorprofileapi.AppArmorProfile{
				Spec: apparmorprofileapi.AppArmorProfileSpec{
					Abstract: r.generateAppArmorProfile(uint32(mntns)),
				},
			}
			parts = append(parts, &profile)
		}

		profile, err := recordingmerger.MergeProfiles(parts)
		if err != nil {
			return fmt.Errorf("merge profiles: %w", err)
		}

		prof, ok := profile.(*apparmorprofileapi.AppArmorProfile)
		if !ok {
			return fmt.Errorf("unexpected non-apparmor profile: %+v", prof)
		}

		spec = prof.Spec
	}

	defer func() {
		log.Printf("Wrote apparmor profile to: %s", r.outFile())
	}()

	if r.options.typ == TypeRawAppArmor {
		return r.buildAppArmorProfileRaw(writer, &spec)
	}

	return r.buildAppArmorProfileCRD(writer, &spec)
}

func (r *Recorder) buildProfile(writer io.Writer, names []string) error {
	arch, err := r.goArchToSeccompArch(runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("get seccomp arch: %w", err)
	}

	if len(r.options.baseSyscalls) > 0 {
		diff := []string{}

		for _, syscall := range r.options.baseSyscalls {
			if !util.Contains(names, syscall) {
				names = append(names, syscall)
				diff = append(diff, syscall)
			}
		}

		log.Printf("Adding base syscalls: %s", strings.Join(diff, ", "))
	}

	sort.Strings(names)

	spec := seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccomp.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []*seccompprofileapi.Syscall{{
			Action: seccomp.ActAllow,
			Names:  names,
		}},
	}

	defer func() {
		log.Printf("Wrote seccomp profile to: %s", r.outFile())
	}()

	if r.options.typ == TypeRawSeccomp {
		return r.buildProfileRaw(writer, &spec)
	}

	return r.buildProfileCRD(writer, &spec)
}

func (r *Recorder) buildProfileRaw(writer io.Writer, spec *seccompprofileapi.SeccompProfileSpec) error {
	data, err := r.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON profile: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("write JSON file: %w", err)
	}

	return nil
}

func (r *Recorder) buildProfileCRD(writer io.Writer, spec *seccompprofileapi.SeccompProfileSpec) error {
	profile := &seccompprofileapi.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SeccompProfile",
			APIVersion: seccompprofileapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: filepath.Base(r.options.commandOptions.Command()),
		},
		Spec: *spec,
	}

	printer := printers.YAMLPrinter{}
	if err := r.PrintObj(printer, profile, writer); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	return nil
}

func (r *Recorder) buildAppArmorProfileCRD(writer io.Writer, spec *apparmorprofileapi.AppArmorProfileSpec) error {
	profile := &apparmorprofileapi.AppArmorProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AppArmorProfile",
			APIVersion: apparmorprofileapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: filepath.Base(r.options.commandOptions.Command()),
		},
		Spec: *spec,
	}

	printer := printers.YAMLPrinter{}
	if err := r.PrintObj(printer, profile, writer); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	if r.options.typ == TypeAll {
		if _, err := writer.Write([]byte("\n---\n")); err != nil {
			return fmt.Errorf("write combined profile: %w", err)
		}
	}

	return nil
}

func (r *Recorder) buildAppArmorProfileRaw(writer io.Writer, spec *apparmorprofileapi.AppArmorProfileSpec) error {
	programName, err := filepath.Abs(r.options.commandOptions.Command())
	if err != nil {
		return fmt.Errorf("get program name: %w", err)
	}

	abstract := spec.Abstract

	raw, err := crd2armor.GenerateProfile(programName, spec.ComplainMode, &abstract)
	if err != nil {
		return fmt.Errorf("build raw apparmor profile: %w", err)
	}

	if _, err := writer.Write([]byte(raw)); err != nil {
		return fmt.Errorf("write AppArmor file: %w", err)
	}

	return nil
}

func (r *Recorder) goArchToSeccompArch(goarch string) (seccompprofileapi.Arch, error) {
	seccompArch, err := r.GoArchToSeccompArch(goarch)
	if err != nil {
		return "", fmt.Errorf("convert golang to seccomp arch: %w", err)
	}

	return seccompprofileapi.Arch(seccompArch), nil
}
