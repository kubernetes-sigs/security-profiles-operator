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
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	// initConfigFd is the file descriptor the run helper reads its
	// configuration from, the first of exec.Cmd.ExtraFiles.
	initConfigFd = 3

	// initFailedExitCode is the exit code of the run helper if it cannot
	// execute the command, like a shell uses it for commands it cannot run.
	initFailedExitCode = 127

	// selfExe is the path of the running spoc binary.
	selfExe = "/proc/self/exe"
)

// initConfig is what the run helper needs to confine and execute the command.
type initConfig struct {
	Profile    *specs.LinuxSeccomp `json:"profile"`
	Path       string              `json:"path"`
	Args       []string            `json:"args"`
	Credential *initCredential     `json:"credential,omitempty"`
}

// initCredential are the user and group the command runs as.
type initCredential struct {
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

// confine returns the command.Options.PreStart hook which starts the command
// through the run helper, a re-execution of spoc which loads the seccomp
// profile and then executes the command. Loading a filter only confines the
// calling thread and spoc cannot control which of its threads forks the
// command, so the filter has to be loaded in the new process right before the
// command gets executed, like container runtimes do.
func confine(profile *specs.LinuxSeccomp) func(*exec.Cmd) (func(), error) {
	return func(cmd *exec.Cmd) (func(), error) {
		config := &initConfig{
			Profile: profile,
			Path:    cmd.Path,
			Args:    cmd.Args,
		}

		// Without no_new_privs, loading the filter needs the privileges
		// which get dropped for the command, so the helper drops them itself
		// once the filter is in place.
		if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
			config.Credential = &initCredential{
				UID: cmd.SysProcAttr.Credential.Uid,
				GID: cmd.SysProcAttr.Credential.Gid,
			}
			cmd.SysProcAttr.Credential = nil
		}

		content, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("marshal run helper config: %w", err)
		}

		reader, writer, err := os.Pipe()
		if err != nil {
			return nil, fmt.Errorf("create run helper pipe: %w", err)
		}

		// The pipe buffer may be smaller than the profile, so write it while
		// the helper reads. The write fails once the helper is gone.
		go func() {
			if _, err := writer.Write(content); err != nil {
				log.Printf("Unable to pass the profile to the run helper: %v", err)
			}

			if err := writer.Close(); err != nil {
				log.Printf("Unable to close the run helper pipe: %v", err)
			}
		}()

		cmd.Path = selfExe
		cmd.Args = []string{os.Args[0], InitArg}
		cmd.ExtraFiles = []*os.File{reader}

		return func() {
			if err := reader.Close(); err != nil {
				log.Printf("Unable to close the run helper pipe: %v", err)
			}
		}, nil
	}
}

// Init runs the run helper if the process got started as one, in which case
// it never returns. The helper loads the seccomp profile and executes the
// command with it. It has to be called at the very beginning of main.
func Init() {
	if len(os.Args) < 2 || os.Args[1] != InitArg {
		return
	}

	// The filter confines the calling thread only, which therefore has to be
	// the one executing the command. Leaving the thread locked keeps the Go
	// runtime from reusing it.
	runtime.LockOSThread()

	err := runInit(os.NewFile(initConfigFd, "run-helper-config"))
	fmt.Fprintf(os.Stderr, "spoc run: %v\n", err)
	os.Exit(initFailedExitCode)
}

// runInit loads the seccomp profile and executes the command. It only returns
// on failure.
func runInit(configFile *os.File) error {
	config := &initConfig{}
	decodeErr := json.NewDecoder(configFile).Decode(config)

	if err := configFile.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}

	if decodeErr != nil {
		return fmt.Errorf("read config: %w", decodeErr)
	}

	if err := loadSeccomp(config.Profile); err != nil {
		return err
	}

	// Everything from here on is subject to the profile, as a container
	// runtime would do it.
	if config.Credential != nil {
		if err := dropPrivileges(config.Credential); err != nil {
			return err
		}
	}

	//nolint:gosec // executing the command of the user is the purpose
	err := syscall.Exec(config.Path, config.Args, os.Environ())

	return fmt.Errorf("execute %s: %w", config.Path, err)
}

// loadSeccomp loads the profile for the calling thread. Unprivileged users
// need no_new_privs for that, which is only set if necessary because it
// prevents setuid binaries from gaining privileges.
func loadSeccomp(profile *specs.LinuxSeccomp) error {
	load := func() error {
		config, err := specconv.SetupSeccomp(profile)
		if err != nil {
			return fmt.Errorf("convert profile: %w", err)
		}

		if _, err := seccomp.InitSeccomp(config); err != nil {
			return fmt.Errorf("load seccomp profile: %w", err)
		}

		return nil
	}

	err := load()
	if !errors.Is(err, unix.EACCES) {
		return err
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}

	return load()
}

// dropPrivileges switches the calling thread to the credential, the same way
// Go's fork/exec does it, since the profile is subject to it. The raw
// syscalls change the calling thread only, which is enough because it is the
// one executing the command. For a privileged caller, setgid and setuid set
// the real, effective and saved IDs.
func dropPrivileges(credential *initCredential) error {
	if _, _, errno := unix.RawSyscall(sysSetgroups, 0, 0, 0); errno != 0 {
		return fmt.Errorf("drop supplementary groups: %w", errno)
	}

	if _, _, errno := unix.RawSyscall(sysSetgid, uintptr(credential.GID), 0, 0); errno != 0 {
		return fmt.Errorf("set group ID %d: %w", credential.GID, errno)
	}

	if _, _, errno := unix.RawSyscall(sysSetuid, uintptr(credential.UID), 0, 0); errno != 0 {
		return fmt.Errorf("set user ID %d: %w", credential.UID, errno)
	}

	return nil
}
