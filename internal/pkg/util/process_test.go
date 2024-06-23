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
	"fmt"
	"os"
	"path"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindPIDByName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		pid       int
		cmd       string
		cmdline   string
		create    bool
		skipCmd   bool
		emptyCmd  bool
		wantError bool
	}{
		{
			name:      "Find PID successfully",
			pid:       123,
			cmd:       "/security-profiles-operator/test/spoc/demobinary",
			cmdline:   "/security-profiles-operator/test/spoc/demobinary--net-tcp--sleep60",
			create:    true,
			skipCmd:   false,
			wantError: false,
		},
		{
			name:      "No pid available",
			create:    false,
			wantError: true,
		},
		{
			name:      "No cmd available",
			pid:       123,
			cmd:       "test-cmd",
			create:    true,
			skipCmd:   true,
			wantError: true,
		},
		{
			name:      "Find PID successfully",
			pid:       123,
			cmd:       "test-cmd",
			cmdline:   "test-cmd",
			create:    true,
			skipCmd:   false,
			emptyCmd:  true,
			wantError: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()
			if tc.create {
				err := createProcData(tempDir, tc.pid, tc.cmdline, tc.skipCmd, tc.emptyCmd)
				require.NoError(t, err)
			}
			p := &proc{name: tc.cmd, pid: defaultPID}
			gotPid, gotErr := p.findPIDByName(tempDir)
			if !tc.wantError {
				require.NoError(t, gotErr)
				require.Equal(t, tc.pid, gotPid, "should find a valid PID by process name")
			} else {
				require.Error(t, gotErr)
			}
		})
	}
}

func createProcData(root string, pid int, cmd string, skipCmd, emptyCmd bool) error {
	procPath := path.Join(root, processRoot)
	if err := os.Mkdir(procPath, 0o700); err != nil {
		return fmt.Errorf("creating proc root dir: %w", err)
	}
	procDir := path.Join(procPath, strconv.Itoa(pid))
	if err := os.Mkdir(procDir, 0o700); err != nil {
		return fmt.Errorf("creating proc dir: %w", err)
	}
	if !skipCmd {
		cmdFile := path.Join(procDir, "cmdline")
		if err := os.WriteFile(cmdFile, []byte(cmd), 0o600; err != nil {
			return fmt.Errorf("creating cmd file: %w", err)
		}
	}
	if emptyCmd {
		procDir := path.Join(procPath, "567")
		if err := os.Mkdir(procDir, 0o700); err != nil {
			return fmt.Errorf("creating proc dir: %w", err)
		}
		cmdFile := path.Join(procDir, "cmdline")
		if err := os.WriteFile(cmdFile, []byte(""), 0o600); err != nil {
			return fmt.Errorf("creating cmd file: %w", err)
		}
	}
	return nil
}
