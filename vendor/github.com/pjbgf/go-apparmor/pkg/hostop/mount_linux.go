//go:build linux
// +build linux

package hostop

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	logr "github.com/go-logr/logr"
	"golang.org/x/sys/unix"
)

const (
	// hostNsPath is a link to the host's mnt namespace path.
	// Access to it requires hostPID, in other words, the current process
	// must share the host's PID namespace.
	hostNsPath string = "/proc/1/ns/mnt"

	nsTypeName NsTypeName = Mount
)

type mountHostOp struct {
	opts *hostOpOpts
}

func NewMountHostOp(opts ...HostOpOption) HostOp {
	o := hostOpOpts{
		logger:          logr.Discard(),
		insideContainer: InsideContainer,
		hostPidCheck:    func() bool { return true },
	}

	o.applyOpts(opts...)

	return &mountHostOp{opts: &o}
}

// Do executes an action ensuring that first thread will be within the host's
// mount namespace.
//
// If the caller is being executed inside a container, it first tries to entre
// the host's namespace. After the action is executed the mnt ns is reverted
// back to what it was.
//
// If the caller is being executed at the host, simply executes the action.
func (m *mountHostOp) Do(action func() error) error {
	if m.opts.insideContainer() {
		m.opts.logger.V(2).Info("running inside container")
		if m.opts.hostPidCheck() {
			hostPidNs, err := HostPidNamespace()
			if err != nil {
				return fmt.Errorf("identifying pid namespace: %w", err)
			}

			if !hostPidNs {
				return fmt.Errorf("must run within host PID namespace: %w", err)
			}
		}
		return m.containerDo(action)
	}

	m.opts.logger.V(2).Info("running in the host")
	return action()
}

func (m *mountHostOp) containerDo(action func() error) error {
	var wg sync.WaitGroup
	wg.Add(1)

	handleDo := func() error {
		origFd, err := os.Open(m.currentThreadNsPath())
		if err != nil {
			return err
		}
		defer func() {
			if err := origFd.Close(); err != nil {
				m.opts.logger.V(1).Info(fmt.Sprintf("closing file: %s", err))
			}
		}()

		hostFd, err := os.Open(hostNsPath)
		if err != nil {
			return err
		}
		defer func() {
			if err := hostFd.Close(); err != nil {
				m.opts.logger.V(1).Info(fmt.Sprintf("closing file: %s", err))
			}
		}()

		defer func() {
			if err := m.switchToMountNs(origFd); err != nil {
				m.opts.logger.V(2).Info(fmt.Sprintf("revert to original mount ns: %v", err))
			} else {
				// if can't switch back to original mount namespace,
				// fail-safe by not making the thread with host mount
				// namespace available to other go routines.
				runtime.UnlockOSThread()
			}
		}()

		if err := m.switchToMountNs(hostFd); err != nil {
			return fmt.Errorf("switch to mount ns: %w", err)
		}
		if err := action(); err != nil {
			return fmt.Errorf("running action: %w", err)
		}

		return nil
	}

	var doErr error
	go func() {
		defer wg.Done()
		runtime.LockOSThread()
		doErr = handleDo()
	}()
	wg.Wait()

	return doErr
}

func (m *mountHostOp) switchToMountNs(fd *os.File) error {
	m.logNsInfo(m.currentThreadNsPath())

	if err := unix.Unshare(syscall.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount (%s): %w", fd.Name(), err)
	}
	if err := unix.Setns(int(fd.Fd()), syscall.CLONE_NEWNS); err != nil {
		return fmt.Errorf("set host ns (%s): %w", fd.Name(), err)
	}

	m.logNsInfo(m.currentThreadNsPath())

	return nil
}

func (m *mountHostOp) currentThreadNsPath() string {
	return fmt.Sprintf("/proc/%d/task/%d/%s", os.Getpid(), unix.Gettid(), nsTypeName)
}

func (m *mountHostOp) logNsInfo(nsPath string) {
	fd, err := os.Open(filepath.Clean(nsPath))
	if err != nil {
		return
	}
	defer func() {
		if err := fd.Close(); err != nil {
			m.opts.logger.V(1).Info(fmt.Sprintf("closing file: %s", err))
		}
	}()

	var s unix.Stat_t
	if err := unix.Fstat(int(fd.Fd()), &s); err != nil {
		m.opts.logger.V(2).Info(fmt.Sprintf("fstat ns: %v", err))
		return
	}
	m.opts.logger.V(2).Info(fmt.Sprintf("dev-inode %d:%d ns path: %s", s.Dev, s.Ino, nsPath))
}
