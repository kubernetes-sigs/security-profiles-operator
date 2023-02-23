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
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/acobaugh/osrelease"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/containers/common/pkg/seccomp"
	libseccomp "github.com/seccomp/libseccomp-golang"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/printers"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Recorder is the main structure of this package.
type Recorder struct {
	btfPath string
	pids    *bpf.BPFMap
}

// New returns a new Recorder instance.
func New() *Recorder {
	return &Recorder{}
}

// Run the Recorder with the provided command args and put the resulting
// profile to the path of filename.
func (r *Recorder) Run(filename string, args ...string) error {
	if filename == "" {
		return errors.New("no filename provided")
	}

	if len(args) == 0 {
		return errors.New("no command provided")
	}

	if err := r.load(); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	defer r.unload()

	cmdName := args[0]
	cmd := exec.Command(cmdName, args[1:]...)
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

	if err := r.processData(pid, cmdName, filename); err != nil {
		return fmt.Errorf("build profile: %w", err)
	}

	return nil
}

func (r *Recorder) load() (err error) {
	log.Print("Loading bpf module")
	r.btfPath, err = r.findBtfPath()
	if err != nil {
		return fmt.Errorf("find btf: %w", err)
	}

	bpfObject, ok := bpfObjects[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("architecture %s is currently unsupported", runtime.GOARCH)
	}

	module, err := bpf.NewModuleFromBufferArgs(bpf.NewModuleArgs{
		BPFObjBuff: bpfObject,
		BPFObjName: "cli_recorder.bpf.o",
		BTFObjPath: r.btfPath,
	})
	if err != nil {
		return fmt.Errorf("bpf module: %w", err)
	}

	log.Print("Loading bpf object from module")
	if err := module.BPFLoadObject(); err != nil {
		return fmt.Errorf("bpf object: %w", err)
	}

	const programName = "sys_enter"
	log.Print("Getting bpf program " + programName)
	program, err := module.GetProgram(programName)
	if err != nil {
		return fmt.Errorf("get %s program: %w", programName, err)
	}

	log.Print("Attaching bpf tracepoint")
	if _, err := program.AttachTracepoint("raw_syscalls", programName); err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}

	log.Print("Getting pids map")
	r.pids, err = module.GetMap("pids")
	if err != nil {
		return fmt.Errorf("get syscalls map: %w", err)
	}

	log.Print("Module successfully loaded")
	return nil
}

func (r *Recorder) unload() {
	log.Print("Unloading bpf module")
	r.pids.GetModule().Close()
	os.RemoveAll(r.btfPath)
}

func (r *Recorder) findBtfPath() (string, error) {
	// Use the system btf if possible
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		log.Print("Using system btf file")
		return "", nil
	}

	log.Print("Trying to find matching in-memory btf")

	btf := types.Btf{}
	if err := json.Unmarshal([]byte(btfJSON), &btf); err != nil {
		return "", fmt.Errorf("unmarshal btf JSON: %w", err)
	}

	res, err := osrelease.Read()
	if err != nil {
		return "", fmt.Errorf("read os-release file: %w", err)
	}

	osID := types.Os(res["ID"])
	btfOs, ok := btf[osID]
	if !ok {
		log.Printf("OS not found in btf map: %s", osID)
		return "", nil
	}
	log.Printf("OS found in btf map: %s", osID)

	osVersion := types.OsVersion(res["VERSION_ID"])
	btfOsVersion, ok := btfOs[osVersion]
	if !ok {
		log.Printf("OS version not found in btf map: %s", osVersion)
		return "", nil
	}
	log.Printf("OS version found in btf map: %s", osVersion)

	uname := syscall.Utsname{}
	if err := syscall.Uname(&uname); err != nil {
		return "", fmt.Errorf("uname syscall failed: %w", err)
	}

	arch := types.Arch(util.ToStringInt8(uname.Machine))
	btfArch, ok := btfOsVersion[arch]
	if !ok {
		log.Printf("Architecture not found in btf map: %s", arch)
		return "", nil
	}
	log.Printf("Architecture found in btf map: %s", arch)

	release := util.ToStringInt8(uname.Release)
	kernel := types.Kernel(release)
	btfBytes, ok := btfArch[kernel]
	if !ok {
		log.Printf("Kernel not found in btf map: %s", kernel)
		return "", nil
	}
	log.Printf("Kernel found in btf map: %s", kernel)

	file, err := os.CreateTemp(
		"",
		fmt.Sprintf("spo-btf-%s-%s-%s-%s", osID, osVersion, arch, kernel),
	)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(btfBytes); err != nil {
		return "", fmt.Errorf("write BTF: %w", err)
	}

	log.Printf("Wrote BTF to file: %s", file.Name())
	return file.Name(), nil
}

func (r *Recorder) processData(pid uint32, cmdName, filename string) error {
	log.Printf("Processing recorded data")

	iterator := r.pids.Iterator()
	for iterator.Next() {
		currentPid := binary.LittleEndian.Uint32(iterator.Key())

		if currentPid != pid {
			continue
		}
		log.Print("Found PID in bpf map")

		syscallsValue, err := r.pids.GetValue(unsafe.Pointer(&currentPid))
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
		if err := r.buildProfile(cmdName, filename, syscalls); err != nil {
			return fmt.Errorf("build profile: %w", err)
		}

		return nil
	}

	return fmt.Errorf("find PID %d in bpf data map", pid)
}

func (r *Recorder) buildProfile(name, filename string, syscalls []string) error {
	arch, err := r.goArchToSeccompArch(runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("get seccomp arch: %w", err)
	}

	profileSpec := seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccomp.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []*seccompprofileapi.Syscall{{
			Action: seccomp.ActAllow,
			Names:  syscalls,
		}},
	}

	profile := &seccompprofileapi.SeccompProfile{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SeccompProfile",
			APIVersion: seccompprofileapi.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: profileSpec,
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	printer := printers.YAMLPrinter{}
	if err := printer.PrintObj(profile, file); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}

	log.Printf("Wrote seccomp profile to: %s", filename)
	return nil
}

func (r *Recorder) goArchToSeccompArch(goarch string) (seccompprofileapi.Arch, error) {
	seccompArch, err := seccomp.GoArchToSeccompArch(goarch)
	if err != nil {
		return "", fmt.Errorf("convert golang to seccomp arch: %w", err)
	}
	return seccompprofileapi.Arch(seccompArch), nil
}
