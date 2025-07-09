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

package command

import (
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
)

var errNoSudoEnvironment = errors.New("not in a sudo environment")

type Command struct {
	impl
	options *Options
	cmd     *exec.Cmd
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
		err := c.DropSudoPrivileges()
		if err != nil && !errors.Is(err, errNoSudoEnvironment) {
			log.Printf("Failed to drop sudo privileges: %v", err)
		}
	}

	if err := c.CmdStart(c.cmd); err != nil {
		return pid, fmt.Errorf("start command: %w", err)
	}

	// Allow to interrupt
	ch := make(chan os.Signal, 1)
	c.Notify(ch, os.Interrupt)

	go func() {
		<-ch
		log.Printf("Got interrupted, terminating process")

		if err := c.Signal(c.cmd, os.Interrupt); err != nil {
			log.Printf("Unable to terminate process: %v", err)
		}
	}()

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
	cmd := exec.Command(
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

	c.cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
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

func (c *Command) Wait() error {
	return c.CmdWait(c.cmd)
}
