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
	"fmt"
	"log"
	"os"
	"os/exec"
)

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

func (c *Command) Wait() error {
	return c.CmdWait(c.cmd)
}
