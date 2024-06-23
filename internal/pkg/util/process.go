/*
Copyright 2024 The Kubernetes Authors.

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

package util

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	defaultPID  = -1
	processRoot = "/proc"
)

// ErrEmptyPIDName indicates an erorr for a PID with an empty process name.
var ErrEmptyPIDName = errors.New("process Name of given PID is empty")

var procRegexp = regexp.MustCompile(`/*proc/\d+/cmdline`)

// ProcessIDByName is looking up the PID by process name.
func ProcessIDByName(name string) (int, error) {
	p := &proc{
		name: name,
		pid:  defaultPID,
	}
	return p.findPIDByName(processRoot)
}

type proc struct {
	name string
	pid  int
}

func (p *proc) findPIDByName(root string) (int, error) {
	err := filepath.Walk(root, p.walkProc)
	if err != nil {
		return -1, fmt.Errorf("looking for pid of process %q: %w", p.name, err)
	}
	if p.pid != defaultPID {
		return p.pid, nil
	}
	return -1, fmt.Errorf("could not find a valid pid for process name %q", p.name)
}

func (p *proc) walkProc(file string, info os.FileInfo, err error) error {
	// Return already if there is an existing error due to for instance
	// insufficient privileges.
	if err != nil {
		return nil //nolint:nilerr // skip errors due to insufficient permissions
	}

	// Skip paths which doesn't look like /proc/<pid>cmdline.
	if !procRegexp.MatchString(file) {
		return nil
	}

	pid, err := parsePID(file)
	if err != nil {
		return fmt.Errorf("parsing PID from path %s: %w", file, err)
	}

	name, err := parseName(file)
	if err != nil {
		// skip pids without empty command and keep going
		if errors.Is(err, ErrEmptyPIDName) {
			return nil
		}
		return fmt.Errorf("parsing process name from path %s: %w", file, err)
	}

	// Update the PID if we found the process
	if strings.HasPrefix(name, p.name) {
		p.pid = pid
	}

	return nil
}

func parsePID(dir string) (int, error) {
	pidDir, _ := path.Split(dir)
	return strconv.Atoi(path.Base(pidDir))
}

func parseName(file string) (string, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading from %s: %w", file, err)
	}
	name := strings.TrimSpace(string(f))
	if name != "" {
		return name, nil
	}
	return "", ErrEmptyPIDName
}
