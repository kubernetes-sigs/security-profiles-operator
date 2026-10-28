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
	"os"
	"os/exec"
	"os/signal"

	"golang.org/x/sys/unix"
)

type defaultImpl struct{}

//go:generate go run -modfile=../../../../hack/tools/go.mod -mod=readonly github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Notify(chan<- os.Signal, ...os.Signal)
	Stop(chan<- os.Signal)
	Signal(*exec.Cmd, os.Signal) error
	Command(string, ...string) *exec.Cmd
	CmdStart(*exec.Cmd) error
	CmdPid(*exec.Cmd) uint32
	CmdWait(*exec.Cmd) error
	GetHomeDirectory(uid uint32) (string, error)
	GetGroupIDs(uid uint32) ([]uint32, error)
	ForegroundProcessGroup() (int, error)
	ProcessGroup(pid int) (int, error)
	Geteuid() int
}

func (*defaultImpl) Notify(c chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(c, sig...)
}

func (*defaultImpl) Stop(c chan<- os.Signal) {
	signal.Stop(c)
}

func (*defaultImpl) Signal(c *exec.Cmd, sig os.Signal) error {
	return c.Process.Signal(sig)
}

func (*defaultImpl) Command(name string, arg ...string) *exec.Cmd {
	// spoc forwards signals to the command instead of killing it through a
	// context.
	cmd := exec.CommandContext(context.Background(), name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}

func (*defaultImpl) CmdStart(cmd *exec.Cmd) error {
	return cmd.Start()
}

func (*defaultImpl) CmdPid(cmd *exec.Cmd) uint32 {
	//nolint:gosec // PIDs are positive and below the kernel pid_max of 2^22
	return uint32(cmd.Process.Pid)
}

func (*defaultImpl) CmdWait(cmd *exec.Cmd) error {
	return cmd.Wait()
}

func (*defaultImpl) GetHomeDirectory(uid uint32) (string, error) {
	return getHomeDirectory(uid)
}

func (*defaultImpl) GetGroupIDs(uid uint32) ([]uint32, error) {
	return getGroupIDs(uid)
}

// ForegroundProcessGroup returns the foreground process group of the
// controlling terminal of spoc, which gets the signals of the terminal.
func (*defaultImpl) ForegroundProcessGroup() (int, error) {
	tty, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}

	defer unix.Close(tty)

	return unix.IoctlGetInt(tty, unix.TIOCGPGRP)
}

// ProcessGroup returns the process group of the process.
func (*defaultImpl) ProcessGroup(pid int) (int, error) {
	return unix.Getpgid(pid)
}

func (*defaultImpl) Geteuid() int {
	return os.Geteuid()
}
