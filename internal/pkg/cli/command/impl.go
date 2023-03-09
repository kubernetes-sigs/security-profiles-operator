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
	"os"
	"os/exec"
	"os/signal"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Notify(chan<- os.Signal, ...os.Signal)
	Signal(*exec.Cmd, os.Signal) error
	Command(string, ...string) *exec.Cmd
	CmdStart(*exec.Cmd) error
	CmdPid(*exec.Cmd) uint32
	CmdWait(*exec.Cmd) error
}

func (*defaultImpl) Notify(c chan<- os.Signal, sig ...os.Signal) {
	signal.Notify(c, sig...)
}

func (*defaultImpl) Signal(c *exec.Cmd, sig os.Signal) error {
	return c.Process.Signal(sig)
}

func (*defaultImpl) Command(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func (*defaultImpl) CmdStart(cmd *exec.Cmd) error {
	return cmd.Start()
}

func (*defaultImpl) CmdPid(cmd *exec.Cmd) uint32 {
	return uint32(cmd.Process.Pid)
}

func (*defaultImpl) CmdWait(cmd *exec.Cmd) error {
	return cmd.Wait()
}
