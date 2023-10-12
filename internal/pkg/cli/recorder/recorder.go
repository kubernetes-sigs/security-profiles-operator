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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/containers/common/pkg/seccomp"
	"github.com/go-logr/logr"
	libseccomp "github.com/seccomp/libseccomp-golang"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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
	if (r.options.typ == TypeApparmor) || (r.options.typ == TypeRawAppArmor) {
		r.bpfRecorder = bpfrecorder.NewAppArmor(logr.New(&cli.LogSink{}))
	} else {
		r.bpfRecorder = bpfrecorder.NewSeccomp(logr.New(&cli.LogSink{}))
	}
	r.bpfRecorder.FilterProgramName(r.options.commandOptions.Command())
	if err := r.LoadBpfRecorder(r.bpfRecorder); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer r.UnloadBpfRecorder(r.bpfRecorder)

	cmd := command.New(r.options.commandOptions)
	pid, err := r.CommandRun(cmd)
	if err != nil {
		return fmt.Errorf("run command: %w", err)
	}

	mntns, err := r.FindProcMountNamespace(r.bpfRecorder, pid)
	if err != nil {
		return fmt.Errorf("finding mntns for command PID %d: %w", pid, err)
	}

	if err := r.CommandWait(cmd); err != nil {
		log.Printf("Command did not exit successfully: %v", err)
	}

	if (r.options.typ == TypeApparmor) || (r.options.typ == TypeRawAppArmor) {
		if err := r.processAppArmorData(); err != nil {
			return fmt.Errorf("build profile: %w", err)
		}
	} else {
		if err := r.processData(mntns); err != nil {
			return fmt.Errorf("build profile: %w", err)
		}
	}

	return nil
}

func (r *Recorder) processData(mntns uint32) error {
	log.Printf("Processing recorded data")

	it := r.SyscallsIterator(r.bpfRecorder)
	for r.IteratorNext(it) {
		currentMntns := binary.LittleEndian.Uint32(r.IteratorKey(it))
		if currentMntns != mntns {
			continue
		}
		log.Printf("Found process mntns %d in bpf map", mntns)

		syscallsValue, err := r.SyscallsGetValue(r.bpfRecorder, currentMntns)
		if err != nil {
			return fmt.Errorf("get syscalls from bpf map: %w", err)
		}

		syscalls := []string{}
		for id, found := range syscallsValue {
			if found != 0 {
				name, err := r.GetName(libseccomp.ScmpSyscall(id))
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

	return fmt.Errorf("find mntns %d in bpf data map", mntns)
}

func (r *Recorder) generateAppArmorProfile() apparmorprofileapi.AppArmorAbstract {
	processed := r.bpfRecorder.GetAppArmorProcessed()

	abstract := apparmorprofileapi.AppArmorAbstract{}
	enabled := true
	var gotExec bool

	exec := apparmorprofileapi.AppArmorExecutablesRules{}
	if len(processed.FileProcessed.AllowedExecutables) != 0 {
		sort.Strings(processed.FileProcessed.AllowedExecutables)
		exec.AllowedExecutables = &processed.FileProcessed.AllowedExecutables
		gotExec = true
	}
	if len(processed.FileProcessed.AllowedLibraries) != 0 {
		sort.Strings(processed.FileProcessed.AllowedLibraries)
		exec.AllowedLibraries = &processed.FileProcessed.AllowedLibraries
		gotExec = true
	}

	if gotExec {
		abstract.Executable = &exec
	}

	if (len(processed.FileProcessed.ReadOnlyPaths) != 0) ||
		(len(processed.FileProcessed.WriteOnlyPaths) != 0) ||
		(len(processed.FileProcessed.ReadWritePaths) != 0) {
		files := apparmorprofileapi.AppArmorFsRules{}
		if len(processed.FileProcessed.ReadOnlyPaths) != 0 {
			sort.Strings(processed.FileProcessed.ReadOnlyPaths)
			files.ReadOnlyPaths = &processed.FileProcessed.ReadOnlyPaths
		}
		if len(processed.FileProcessed.WriteOnlyPaths) != 0 {
			sort.Strings(processed.FileProcessed.WriteOnlyPaths)
			files.WriteOnlyPaths = &processed.FileProcessed.WriteOnlyPaths
		}
		if len(processed.FileProcessed.ReadWritePaths) != 0 {
			sort.Strings(processed.FileProcessed.ReadWritePaths)
			files.ReadWritePaths = &processed.FileProcessed.ReadWritePaths
		}
		abstract.Filesystem = &files
	}

	if processed.Socket.UseRaw || processed.Socket.UseTcp || processed.Socket.UseUdp {
		net := apparmorprofileapi.AppArmorNetworkRules{}
		proto := apparmorprofileapi.AppArmorAllowedProtocols{}
		if processed.Socket.UseRaw {
			net.AllowRaw = &enabled
		}
		if processed.Socket.UseTcp {
			proto.AllowTcp = &enabled
			net.Protocols = &proto
		}
		if processed.Socket.UseUdp {
			proto.AllowUdp = &enabled
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

func (r *Recorder) processAppArmorData() error {
	abstract := r.generateAppArmorProfile()
	spec := apparmorprofileapi.AppArmorProfileSpec{
		Abstract: abstract,
	}
	defer func() {
		log.Printf("Wrote apparmor profile to: %s", r.options.outputFile)
	}()

	if r.options.typ == TypeRawAppArmor {
		return r.buildAppArmorProfileRaw(&spec)
	}
	return r.buildAppArmorProfileCRD(&spec)
}

func (r *Recorder) buildProfile(names []string) error {
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

	data, err := r.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON profile: %w", err)
	}

	const defaultMode os.FileMode = 0o644
	if err := r.WriteFile(r.options.outputFile, data, defaultMode); err != nil {
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
			Name: filepath.Base(r.options.commandOptions.Command()),
		},
		Spec: *spec,
	}

	file, err := r.Create(r.options.outputFile)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer r.CloseFile(file)

	printer := printers.YAMLPrinter{}
	if err := r.PrintObj(printer, profile, file); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	return nil
}

func (r *Recorder) buildAppArmorProfileCRD(spec *apparmorprofileapi.AppArmorProfileSpec) error {
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

	file, err := r.Create(r.options.outputFile)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer r.CloseFile(file)

	printer := printers.YAMLPrinter{}
	if err := r.PrintObj(printer, profile, file); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	return nil
}

func (r *Recorder) buildAppArmorProfileRaw(spec *apparmorprofileapi.AppArmorProfileSpec) error {
	if r.options.outputFile == DefaultOutputFile {
		r.options.outputFile = strings.ReplaceAll(r.options.outputFile, ".yaml", ".apparmor")
	}

	abstract := spec.Abstract
	raw, err := crd2armor.GenerateProfile(r.options.commandOptions.Command(), &abstract)
	if err != nil {
		return err
	}

	const defaultMode os.FileMode = 0o644
	if err := r.WriteFile(r.options.outputFile, []byte(raw), defaultMode); err != nil {
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
