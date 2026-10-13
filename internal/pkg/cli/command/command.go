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

package command

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errNoSudoEnvironment = errors.New("not in a sudo environment")

// forwardedSignals are the signals which are forwarded to the command instead
// of terminating spoc, so that the command can shut down and spoc still
// processes its result.
var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}

type Command struct {
	impl
	options *Options
	cmd     *exec.Cmd
	signals chan os.Signal
}

// New returns a new Command instance.
func New(options *Options) *Command {
	return &Command{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Command.
func (c *Command) Run() (pid uint32, err error) {
	c.cmd = c.Command(c.options.command, c.options.args...)
	if c.options.DropSudoPrivileges {
		// Running the command as root instead would give it privileges the
		// invoking user did not ask for.
		err := c.DropSudoPrivileges()
		if err != nil && !errors.Is(err, errNoSudoEnvironment) {
			return pid, fmt.Errorf(
				"drop sudo privileges, use --%s to run the command as root: %w",
				FlagPrivileged, err,
			)
		}
	}

	if c.options.PreStart != nil {
		postStart, err := c.options.PreStart(c.cmd)
		if err != nil {
			return pid, fmt.Errorf("prepare command: %w", err)
		}

		if postStart != nil {
			defer postStart()
		}
	}

	// Subscribe before the start, a signal in between would otherwise
	// terminate spoc and leave the command running.
	c.signals = make(chan os.Signal, len(forwardedSignals))
	c.Notify(c.signals, forwardedSignals...)

	if err := c.CmdStart(c.cmd); err != nil {
		c.stopSignals()

		return pid, fmt.Errorf("start command: %w", err)
	}

	pid = c.CmdPid(c.cmd)
	log.Printf("Running command with PID: %d", pid)

	go c.forwardSignals(c.signals, pid)

	return pid, nil
}

// lookupTimeout bounds the lookups of the home directory with getent(1) and
// of the supplementary groups with id(1), whose NSS backend may hang.
const lookupTimeout = 10 * time.Second

// getHomeDirectory returns the home directory of the user. getent(1) goes
// through NSS and sees the users of directory services like SSSD or LDAP,
// which the user database of spoc, built without cgo, does not.
func getHomeDirectory(uid uint32) (string, error) {
	uidString := strconv.FormatUint(uint64(uid), 10)

	usr, err := user.LookupId(uidString)
	if err == nil && usr.HomeDir != "" {
		return usr.HomeDir, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	//nolint:gosec // a fixed command with a numeric user ID
	out, err := exec.CommandContext(ctx, "getent", "passwd", uidString).Output()
	if err != nil {
		return "", fmt.Errorf("home dir lookup failed: %w", err)
	}

	return passwdHomeDirectory(string(out))
}

// passwdHomeDirectory returns the home directory of a passwd entry, which
// has the fields name:password:uid:gid:gecos:home:shell.
func passwdHomeDirectory(entry string) (string, error) {
	const homeField, fields = 5, 7

	parts := strings.Split(strings.TrimSpace(entry), ":")
	if len(parts) != fields || parts[homeField] == "" {
		return "", fmt.Errorf("home dir lookup failed: unexpected passwd entry %q", entry)
	}

	return parts[homeField], nil
}

// getGroupIDs returns the supplementary groups of the user. id(1) goes
// through NSS and sees the groups of directory services like SSSD or LDAP,
// which the user database of spoc, built without cgo, does not. The groups of
// /etc/group are the fallback for systems where id fails, hangs or prints
// something else than group IDs.
func getGroupIDs(uid uint32) ([]uint32, error) {
	uidString := strconv.FormatUint(uint64(uid), 10)

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	//nolint:gosec // a fixed command with a numeric user ID
	out, err := exec.CommandContext(ctx, "id", "-G", uidString).Output()
	if err == nil {
		ids, parseErr := parseGroupIDs(strings.Fields(string(out)))
		if parseErr == nil {
			return ids, nil
		}

		err = parseErr
	}

	usr, lookupErr := user.LookupId(uidString)
	if lookupErr != nil {
		return nil, fmt.Errorf("group lookup failed: %w", errors.Join(err, lookupErr))
	}

	groups, lookupErr := usr.GroupIds()
	if lookupErr != nil {
		return nil, fmt.Errorf("group lookup failed: %w", errors.Join(err, lookupErr))
	}

	return parseGroupIDs(groups)
}

// parseGroupIDs parses the numeric group IDs.
func parseGroupIDs(groups []string) ([]uint32, error) {
	ids := make([]uint32, 0, len(groups))

	for _, group := range groups {
		id, err := strconv.ParseUint(group, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse group ID %q: %w", group, err)
		}

		ids = append(ids, uint32(id))
	}

	return ids, nil
}

// sudoIDs returns the user and group ID of the user who invoked spoc through
// sudo, or errNoSudoEnvironment.
func sudoIDs() (uid, gid uint32, err error) {
	parsedUID, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil {
		return 0, 0, errNoSudoEnvironment
	}

	parsedGID, err := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32)
	if err != nil {
		return 0, 0, errNoSudoEnvironment
	}

	return uint32(parsedUID), uint32(parsedGID), nil
}

func (c *Command) DropSudoPrivileges() error {
	uid, gid, err := sudoIDs()
	if err != nil {
		return err
	}

	userName := os.Getenv("SUDO_USER")
	if userName == "" {
		return errNoSudoEnvironment
	}

	home, err := c.GetHomeDirectory(uid)
	if err != nil {
		return fmt.Errorf("failed to drop privileges: %w", err)
	}

	// Without them, the command would lack the access the user has through
	// supplementary groups, like the docker group, and record a different
	// profile than it would produce without sudo. If they cannot be looked
	// up, the command runs without supplementary groups.
	groups, err := c.GetGroupIDs(uid)
	if err != nil {
		log.Printf("WARNING: running the command without the supplementary groups of user %d: %v",
			uid, err)

		groups = nil
	}

	c.cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: groups,
		},
	}
	// sudo sets USER and LOGNAME to the target user, which tools like git
	// take as the name of the user.
	c.cmd.Env = append(
		slices.DeleteFunc(
			c.cmd.Environ(),
			func(s string) bool { return strings.HasPrefix(s, "SUDO_") },
		),
		"HOME="+home,
		"USER="+userName,
		"LOGNAME="+userName,
	)

	return nil
}

// ErrNotSingleRegularFile is returned by CreateFile if the file to hand to
// the sudo user is not a regular file with a single link.
var ErrNotSingleRegularFile = errors.New("not a regular file with a single link")

// CreateFile creates or truncates the file for writing, like os.Create with
// the permissions. If spoc runs as root through sudo and the directory of the
// file belongs to the invoking user, the file is handed to that user, who
// could neither change nor replace it otherwise, for example on a later
// invocation without sudo. A file elsewhere, like in a system directory,
// keeps its owner.
//
// The user controls that directory, so the file is opened without following
// a symlink, has to be a regular file with a single link before anything
// gets written to it, and is handed over through its descriptor.
func CreateFile(name string, perm os.FileMode) (*os.File, error) {
	return createFile(name, perm, os.Geteuid(), (*os.File).Chown)
}

func createFile(
	name string, perm os.FileMode, euid int, chown func(*os.File, int, int) error,
) (*os.File, error) {
	uid, gid, err := sudoIDs()

	// A name of a directory fails to open as before, filepath.Dir and
	// filepath.Base would name a file in it otherwise.
	if euid != 0 || err != nil || strings.HasSuffix(name, string(filepath.Separator)) {
		return createPlainFile(name, perm)
	}

	// The owner gets checked on the opened directory, which may as well be
	// reached through a symlink.
	dir, err := os.OpenFile(filepath.Dir(name), os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return createPlainFile(name, perm)
	}

	defer dir.Close()

	if owner, err := fileOwner(dir); err != nil || owner != uid {
		return createPlainFile(name, perm)
	}

	// Truncating has to wait for the checks, a hard link may lead anywhere.
	// Without O_NONBLOCK, a FIFO would block the open.
	fd, err := unix.Openat(
		int(dir.Fd()), filepath.Base(name),
		unix.O_WRONLY|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC,
		uint32(perm.Perm()),
	)
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf(
			"refusing to write through the symlink %s as root, pass its target instead: %w",
			name, err,
		)
	}

	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}

	file := os.NewFile(uintptr(fd), name)

	if err := handOver(file, uid, gid, chown); err != nil {
		file.Close()

		return nil, err
	}

	return file, nil
}

// createPlainFile creates or truncates the file for writing, like os.Create
// with the permissions.
func createPlainFile(name string, perm os.FileMode) (*os.File, error) {
	//nolint:gosec // the file the user asked for
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
}

// handOver checks that the file is a regular file with a single link,
// truncates it and gives it to the user. A failure to change the owner only
// gets logged, the file stays owned by root then.
func handOver(file *os.File, uid, gid uint32, chown func(*os.File, int, int) error) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return fmt.Errorf("stat %s: %w", file.Name(), err)
	}

	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return fmt.Errorf("refusing to write %s: %w", file.Name(), ErrNotSingleRegularFile)
	}

	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate %s: %w", file.Name(), err)
	}

	// The IDs are unsigned 32-bit values, the ones from 1<<31 on would overflow
	// the int of a 32-bit platform. systemd advises against such IDs anyway.
	if uid > math.MaxInt32 || gid > math.MaxInt32 {
		log.Printf(
			"WARNING: keeping %s owned by root: IDs %d:%d out of range",
			file.Name(),
			uid,
			gid,
		)

		return nil
	}

	if err := chown(file, int(uid), int(gid)); err != nil {
		log.Printf("WARNING: keeping %s owned by root: %v", file.Name(), err)
	}

	return nil
}

// fileOwner returns the user ID owning the open file.
func fileOwner(file *os.File) (uint32, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return 0, err
	}

	return stat.Uid, nil
}

// forwardSignals forwards every received signal to the command with the
// process ID until the channel gets closed.
func (c *Command) forwardSignals(signals <-chan os.Signal, pid uint32) {
	for sig := range signals {
		// The terminal sends the SIGINT of Ctrl+C to its whole foreground
		// process group. If the command is part of it, forwarding would
		// deliver it twice, which many programs take as a request to abort
		// their shutdown. While the command runs in the foreground of a
		// terminal, a SIGINT sent to spoc alone therefore does not reach it.
		if sig == os.Interrupt && c.inTerminalForeground(pid) {
			log.Printf("Got %v, the process gets it from the terminal as well", sig)

			continue
		}

		log.Printf("Got %v, forwarding it to the process", sig)

		if err := c.Signal(c.cmd, sig); err != nil {
			log.Printf("Unable to forward %v to the process: %v", sig, err)
		}
	}
}

// inTerminalForeground reports whether the process is in the foreground
// process group of the controlling terminal of spoc. The command may have
// moved to a process group of its own, like timeout(1) does.
func (c *Command) inTerminalForeground(pid uint32) bool {
	foreground, err := c.ForegroundProcessGroup()
	if err != nil || foreground <= 0 {
		return false
	}

	group, err := c.ProcessGroup(int(pid))

	return err == nil && group == foreground
}

// stopSignals restores the default signal handling and ends the forwarding.
func (c *Command) stopSignals() {
	if c.signals == nil {
		return
	}

	c.Stop(c.signals)
	close(c.signals)
	c.signals = nil
}

// Wait waits for the command to exit. Signals are forwarded to the command
// until then.
func (c *Command) Wait() error {
	defer c.stopSignals()

	return c.CmdWait(c.cmd)
}

// ExitCode returns the exit code of a command which ran but did not succeed,
// the way a shell reports it: the exit status, or 128 plus the signal number
// if the command got killed by a signal. It returns false if err does not
// come from the exit of the command.
func ExitCode(err error) (int, bool) {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return 0, false
	}

	const signalOffset = 128
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return signalOffset + int(status.Signal()), true
	}

	return exitErr.ExitCode(), true
}
