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
	"strconv"
	"syscall"
	"unsafe"

	"github.com/opencontainers/runc/libcontainer/seccomp"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	// firstExtraFd is the file descriptor of the first of exec.Cmd.ExtraFiles.
	firstExtraFd = 3

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

// initCredential are the user and groups the command runs as.
type initCredential struct {
	UID    uint32   `json:"uid"`
	GID    uint32   `json:"gid"`
	Groups []uint32 `json:"groups,omitempty"`
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
				UID:    cmd.SysProcAttr.Credential.Uid,
				GID:    cmd.SysProcAttr.Credential.Gid,
				Groups: cmd.SysProcAttr.Credential.Groups,
			}
			cmd.SysProcAttr.Credential = nil
		}

		content, err := json.Marshal(config)
		if err != nil {
			return nil, fmt.Errorf("marshal run helper config: %w", err)
		}

		inherited, err := inheritedFds()
		if err != nil {
			return nil, err
		}

		copies, err := dupInherited(inherited)
		if err != nil {
			return nil, err
		}

		reader, writer, err := os.Pipe()
		if err != nil {
			closeFiles(copies)

			return nil, fmt.Errorf("create run helper pipe: %w", err)
		}

		// The pipe buffer may be smaller than the profile, so write it while
		// the helper reads. The write fails with a broken pipe once the
		// helper is gone, like when it could not be started, which the
		// caller reports already.
		go func() {
			if _, err := writer.Write(content); err != nil && !errors.Is(err, syscall.EPIPE) {
				log.Printf("Unable to pass the profile to the run helper: %v", err)
			}

			if err := writer.Close(); err != nil {
				log.Printf("Unable to close the run helper pipe: %v", err)
			}
		}()

		var configFd int

		cmd.Path = selfExe
		cmd.ExtraFiles, configFd = extraFiles(inherited, copies, reader)
		cmd.Args = []string{os.Args[0], InitArg, strconv.Itoa(configFd)}

		return func() {
			if err := reader.Close(); err != nil {
				log.Printf("Unable to close the run helper pipe: %v", err)
			}

			closeFiles(copies)
		}, nil
	}
}

// inheritedFds returns the file descriptors from firstExtraFd on which spoc
// inherited and which the command inherits therefore, like the ones a shell
// opens with a redirection like 3>file. Go opens its own files with
// FD_CLOEXEC.
func inheritedFds() ([]int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, fmt.Errorf("list file descriptors: %w", err)
	}

	var fds []int

	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd < firstExtraFd {
			continue
		}

		// The descriptor of the directory listing is gone already.
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			continue
		}

		fds = append(fds, fd)
	}

	return fds, nil
}

// dupInherited returns copies of the inherited file descriptors, which the
// run helper gets passed at the numbers of the originals. A file which wraps
// a descriptor closes it once it gets garbage collected, so the originals,
// which spoc does not own, must not be wrapped. The caller closes the copies.
func dupInherited(inherited []int) ([]*os.File, error) {
	copies := make([]*os.File, 0, len(inherited))

	for _, fd := range inherited {
		dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			closeFiles(copies)

			return nil, fmt.Errorf("duplicate inherited file descriptor %d: %w", fd, err)
		}

		copies = append(copies, os.NewFile(uintptr(dup), "inherited-"+strconv.Itoa(fd)))
	}

	return copies, nil
}

// closeFiles closes the files, logging the failures.
func closeFiles(files []*os.File) {
	for _, file := range files {
		if err := file.Close(); err != nil {
			log.Printf("Unable to close %s: %v", file.Name(), err)
		}
	}
}

// extraFiles returns the exec.Cmd.ExtraFiles which pass the copies of the
// inherited file descriptors at the numbers of the originals and the config
// after them, and the file descriptor of the config in the run helper. The
// gaps get closed, which the execution of the command would do anyway. The
// child moves a copy whose number is a lower target out of the way before it
// places the files, see syscall.ProcAttr.
func extraFiles(
	inherited []int,
	copies []*os.File,
	config *os.File,
) (files []*os.File, configFd int) {
	configFd = firstExtraFd
	for _, fd := range inherited {
		configFd = max(configFd, fd+1)
	}

	files = make([]*os.File, configFd-firstExtraFd+1)
	for i, fd := range inherited {
		files[fd-firstExtraFd] = copies[i]
	}

	files[configFd-firstExtraFd] = config

	return files, configFd
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

	configFd := firstExtraFd

	if len(os.Args) > 2 {
		fd, err := strconv.Atoi(os.Args[2])
		if err != nil || fd < firstExtraFd {
			fmt.Fprintf(os.Stderr, "spoc run: invalid config file descriptor %q\n", os.Args[2])
			os.Exit(initFailedExitCode)
		}

		configFd = fd
	}

	err := runInit(os.NewFile(uintptr(configFd), "run-helper-config"))
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

	if err := keepFileLimit(); err != nil {
		return err
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

// keepFileLimit keeps the RLIMIT_NOFILE soft limit as it is when the command
// gets executed. Go raises it at startup and syscall.Exec sets it back right
// before the execve, which would then be subject to the profile: a profile
// which kills on prlimit64 would kill the run helper, and one which logs it
// would report a syscall the command never made. Setting the limit makes Go
// skip that, so the command gets the raised limit, like it does whenever the
// profile denies prlimit64, which recorded profiles usually do.
func keepFileLimit() error {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("get file limit: %w", err)
	}

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("set file limit: %w", err)
	}

	return nil
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
	// setgroups takes the address of the list, like in Go's fork/exec. The
	// conversion to uintptr stays in the call expression, which keeps the
	// list alive for the call.
	var groups *uint32
	if len(credential.Groups) > 0 {
		groups = &credential.Groups[0]
	}

	if _, _, errno := unix.RawSyscall(
		sysSetgroups,
		uintptr(len(credential.Groups)),
		uintptr(unsafe.Pointer(groups)), //nolint:gosec // see above
		0,
	); errno != 0 {
		return fmt.Errorf("set supplementary groups: %w", errno)
	}

	if _, _, errno := unix.RawSyscall(sysSetgid, uintptr(credential.GID), 0, 0); errno != 0 {
		return fmt.Errorf("set group ID %d: %w", credential.GID, errno)
	}

	if _, _, errno := unix.RawSyscall(sysSetuid, uintptr(credential.UID), 0, 0); errno != 0 {
		return fmt.Errorf("set user ID %d: %w", credential.UID, errno)
	}

	return nil
}
