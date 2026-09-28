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

package enricher

import (
	"os"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func Test_extractSPORequestUID(t *testing.T) {
	t.Parallel()

	type args struct {
		input string
	}

	tests := []struct {
		name      string
		args      args
		want      string
		foundWant bool
	}{
		{
			name: "Basic test with cmdline having SPO_EXEC_REQUEST_UID",
			args: args{
				input: "env SPO_EXEC_REQUEST_UID=dbbf5fca-c955-4922-99d2-27a50212071c ls",
			},
			want:      "dbbf5fca-c955-4922-99d2-27a50212071c",
			foundWant: true,
		},
		{
			name:      "Test with no value",
			args:      args{input: "ls"},
			want:      "",
			foundWant: false,
		},
		{
			name:      "Test with other env values",
			args:      args{input: "env INVALID=dbbf5fca-c955-4922-99d2-27a50212071c ls"},
			want:      "",
			foundWant: false,
		},
		{
			name:      "Test with process values",
			args:      args{input: "nginx: master process nginx -g daemon off;"},
			want:      "",
			foundWant: false,
		},
		{
			name:      "Test with no data",
			args:      args{input: ""},
			want:      "",
			foundWant: false,
		},
		{
			name:      "Test with blank data",
			args:      args{input: "env SPO_EXEC_REQUEST_UID= ls"},
			want:      "",
			foundWant: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, got1 := extractSPORequestUID(tt.args.input)

			if got != tt.want {
				t.Errorf("extractSPORequestUID() got = %v, want %v", got, tt.want)
			}

			if got1 != tt.foundWant {
				t.Errorf("extractSPORequestUID() got1 = %v, want %v", got1, tt.foundWant)
			}
		})
	}
}

// TestGetProcessInfoReusedPid asserts that a process reusing the PID of a
// cached one does not get its command line and exec request.
func TestGetProcessInfoReusedPid(t *testing.T) {
	t.Parallel()

	const pid = 42

	cache := ttlcache.New(ttlcache.WithTTL[string, *types.ProcessInfo](time.Hour))
	mock := &enricherfakes.FakeImpl{}

	uid := uint32(1000)

	mock.ProcessStartTimeReturns(time.Second, nil)
	mock.CmdlineForPIDReturns("first "+requestIdEnv+"=first-request", nil)

	first, err := GetProcessInfo(pid, "/bin/first", &uid, nil, cache, mock)
	require.Error(t, err, "the request is not in the environment")
	require.Equal(t, "first "+requestIdEnv+"=first-request", first.CmdLine)
	require.Equal(t, "first-request", *first.ExecRequestId)
	require.Equal(t, "/bin/first", first.Executable)
	require.Equal(t, &uid, first.Uid)

	// Cached for the same process, with the details of the audit line.
	again, err := GetProcessInfo(pid, "/bin/exec", nil, nil, cache, mock)
	require.NoError(t, err)
	require.Equal(t, first.CmdLine, again.CmdLine)
	require.Equal(t, "/bin/exec", again.Executable)
	require.Nil(t, again.Uid)
	require.Equal(t, 1, mock.CmdlineForPIDCallCount())

	// Another process with the PID.
	mock.ProcessStartTimeReturns(time.Minute, nil)
	mock.CmdlineForPIDReturns("second", nil)

	second, err := GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock)
	require.Error(t, err, "the request is not in the environment")
	require.Equal(t, "second", second.CmdLine)
	require.Nil(t, second.ExecRequestId)

	// Lines read after it exited are its own.
	mock.ProcessStartTimeReturns(0, os.ErrNotExist)
	mock.CmdlineForPIDReturns("", os.ErrNotExist)

	gone, err := GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock)
	require.NoError(t, err)
	require.Equal(t, "second", gone.CmdLine)

	// The cached info is never handed out itself.
	gone.CmdLine = "changed"

	again, err = GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock)
	require.NoError(t, err)
	require.Equal(t, "second", again.CmdLine)
}
