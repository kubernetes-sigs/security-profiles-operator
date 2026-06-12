/*
Copyright 2020 The Kubernetes Authors.

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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractContainerID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cgroupLine string
		want       string
	}{
		{
			"Should extract CRI-O ID",
			"4:net_cls,net_prio:/kubepods/besteffort/pod26ba375c-2266-4ecc-bf2d-b626db8762af/" +
				"crio-af208fd68bf39a07a439ed0c9b6609b9ae63ecd8a5f1a2af3e0db48b945b320a",
			"af208fd68bf39a07a439ed0c9b6609b9ae63ecd8a5f1a2af3e0db48b945b320a",
		},
		{
			"Should extract containerd/Docker ID",
			"12:cpu,cpuacct:/kubepods/burstable/poda201f46d-151a-4701-8f24-314bea77df79/" +
				"b469ca5b54e01e7724b7a990f01d54f571dd7669b87851a87bd8b849c438c580",
			"b469ca5b54e01e7724b7a990f01d54f571dd7669b87851a87bd8b849c438c580",
		},
		{
			"Should return empty when not found",
			"0::/system.slice/crio.service",
			"",
		},
		{
			"Should extract CRI-O ID ending with .scope",
			"0::/system.slice/crio-conmon-5819a498721cf8bb7e334809c9e48aa310bfc98801eb8017034ad17fb0749920.scope",
			"5819a498721cf8bb7e334809c9e48aa310bfc98801eb8017034ad17fb0749920",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ContainerIDRegex.FindString(tt.cgroupLine)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGetProcessStartTimeTicks(t *testing.T) {
	t.Parallel()

	filler := "S 1 1234 1234 0 -1 4194560 1234 0 0 0 10 20 30 40 20 0 1 0"

	tests := []struct {
		name        string
		pid         int
		mockContent string
		mockErr     error
		want        string
		wantErr     bool
	}{
		{
			name:        "Standard valid output",
			pid:         1234,
			mockContent: fmt.Sprintf("1234 (bash) %s 88888 1234", filler),
			want:        "88888",
			wantErr:     false,
		},
		{
			name:        "Edge-case: comm field with spaces",
			pid:         1234,
			mockContent: fmt.Sprintf("1234 (my cool daemon) %s 99999 1234", filler),
			want:        "99999",
			wantErr:     false,
		},
		{
			name:        "Edge-case: nested and trailing parentheses",
			pid:         1234,
			mockContent: fmt.Sprintf("1234 (my (cool) daemon()) %s 11111 1234", filler),
			want:        "11111",
			wantErr:     false,
		},
		{
			name:    "Error path: missing /proc/<pid>/stat file",
			pid:     9999,
			mockErr: os.ErrNotExist,
			wantErr: true,
		},
		{
			name:        "Error path: truncated stat output",
			pid:         1234,
			mockContent: "1234 (bash S 1 1234",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockFileReader := func(pid int) ([]byte, error) {
				if tt.mockErr != nil {
					return nil, tt.mockErr
				}

				return []byte(tt.mockContent), nil
			}

			got, err := getProcessStartTimeTicks(tt.pid, mockFileReader)

			if tt.wantErr {
				require.Error(t, err, "expected an error but got none")
			} else {
				require.NoError(t, err, "expected no error but got one")
				require.Equal(t, tt.want, got, "start time ticks did not match")
			}
		})
	}
}

func TestGetProcessStartTimeTicks_CacheMissOnRecycledPID(t *testing.T) {
	t.Parallel()

	pid := 1234
	filler := "S 1 1234 1234 0 -1 4194560 1234 0 0 0 10 20 30 40 20 0 1 0"

	// Execution 1: Mocking the original process
	mockReader1 := func(pid int) ([]byte, error) {
		return fmt.Appendf(nil, "%d (bash) %s 100 1234", pid, filler), nil
	}
	time1, err := getProcessStartTimeTicks(pid, mockReader1)
	require.NoError(t, err)

	// Execution 2: Mocking a new process that reused the same PID
	mockReader2 := func(pid int) ([]byte, error) {
		return fmt.Appendf(nil, "%d (python3) %s 5000 1234", pid, filler), nil
	}
	time2, err := getProcessStartTimeTicks(pid, mockReader2)
	require.NoError(t, err)

	// Verify the start times are distinct to prevent cache collisions
	require.NotEqual(t, time1, time2, "expected different start times for a recycled PID to prevent cache poisoning")
}
