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
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
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

	go c.forwardSignals(c.signals)

	pid = c.CmdPid(c.cmd)
	log.Printf("Running command with PID: %d", pid)

	return pid, nil
}

func getHomeDirectory(uid uint32) (string, error) {
	usr, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err == nil && usr.HomeDir != "" {
		return usr.HomeDir, nil
	}
	//nolint:gosec // uid is trusted here
	cmd := exec.CommandContext(
		context.Background(),
		"sudo",
		fmt.Sprintf("--user=#%d", uid),
		"--set-home",
		"bash",
		"-c",
		"echo -n ~",
	)

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("home dir lookup failed: %w", err)
	}

	if len(out) == 0 {
		return "", errors.New("home dir lookup failed: no output")
	}

	return string(out), nil
}

// groupLookupTimeout bounds the lookup of the supplementary groups with
// id(1), whose NSS backend may hang.
const groupLookupTimeout = 10 * time.Second

// getGroupIDs returns the supplementary groups of the user. id(1) goes
// through NSS and sees the groups of directory services like SSSD or LDAP,
// which the user database of spoc, built without cgo, does not. The groups of
// /etc/group are the fallback for systems where id fails, hangs or prints
// something else than group IDs.
func getGroupIDs(uid uint32) ([]uint32, error) {
	uidString := strconv.FormatUint(uint64(uid), 10)

	ctx, cancel := context.WithTimeout(context.Background(), groupLookupTimeout)
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

func (c *Command) DropSudoPrivileges() error {
	uid, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil {
		return errNoSudoEnvironment
	}

	gid, err := strconv.ParseUint(os.Getenv("SUDO_GID"), 10, 32)
	if err != nil {
		return errNoSudoEnvironment
	}

	userName := os.Getenv("SUDO_USER")
	if userName == "" {
		return errNoSudoEnvironment
	}

	home, err := c.GetHomeDirectory(uint32(uid))
	if err != nil {
		return fmt.Errorf("failed to drop privileges: %w", err)
	}

	// Without them, the command would lack the access the user has through
	// supplementary groups, like the docker group, and record a different
	// profile than it would produce without sudo. If they cannot be looked
	// up, the command runs without supplementary groups.
	groups, err := c.GetGroupIDs(uint32(uid))
	if err != nil {
		log.Printf("WARNING: running the command without the supplementary groups of user %d: %v",
			uid, err)

		groups = nil
	}

	c.cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: groups,
		},
	}
	c.cmd.Env = append(
		slices.DeleteFunc(
			c.cmd.Environ(),
			func(s string) bool { return strings.HasPrefix(s, "SUDO_") },
		),
		"HOME="+home,
		"USER="+userName,
	)

	return nil
}

// forwardSignals forwards every received signal to the command until the
// channel gets closed.
func (c *Command) forwardSignals(signals <-chan os.Signal) {
	for sig := range signals {
		log.Printf("Got %v, forwarding it to the process", sig)

		if err := c.Signal(c.cmd, sig); err != nil {
			log.Printf("Unable to forward %v to the process: %v", sig, err)
		}
	}
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
