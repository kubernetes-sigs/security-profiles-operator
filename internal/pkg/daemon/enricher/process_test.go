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

// TestExecRequestUID asserts that the request of an env command comes from the
// assignment in its arguments which the exec metadata webhook adds, and the one
// of any other process from its environment.
func TestExecRequestUID(t *testing.T) {
	t.Parallel()

	const (
		uid      = "dbbf5fca-c955-4922-99d2-27a50212071c"
		assigned = requestIdEnv + "=" + uid
		forged   = requestIdEnv + "=forged"
	)

	for name, tc := range map[string]struct {
		args     []string
		env      string
		envFound bool
		want     string
	}{
		"env command": {
			args: []string{"env", assigned, "ls"},
			want: uid,
		},
		"arguments before the environment": {
			args: []string{"env", assigned, "ls"}, env: "debug", envFound: true,
			want: uid,
		},
		"prepended env command": {
			args: []string{"env", assigned, "env", "-S", forged + " ls"},
			want: uid,
		},
		"env command after a prepended one": {
			args: []string{"env", "-S", forged + " ls"}, env: uid, envFound: true,
			want: uid,
		},
		"argument with spaces before": {
			args: []string{"env", "MSG=hello " + forged, assigned, "sh", "-c", "echo $MSG"},
			want: uid,
		},
		"value of another assignment": {
			args: []string{"env", "A=" + forged, assigned, "id"},
			want: uid,
		},
		"argument of an option": {
			args: []string{"env", "-C", forged, assigned, "id"},
			want: uid,
		},
		"assignment of a longer name": {
			args: []string{"env", "FOO_" + forged, "id"},
		},
		"argument of the command": {
			args: []string{"env", assigned, "sh", "-c", forged},
			want: uid,
		},
		"env command by path": {
			args: []string{"/usr/bin/env", assigned, "ls"},
			want: uid,
		},
		"environment": {
			args: []string{"ls"}, env: uid, envFound: true,
			want: uid,
		},
		"environment of another command": {
			args: []string{"sh", "-c", "foo", forged}, env: uid, envFound: true,
			want: uid,
		},
		"assignment of another command": {
			args: []string{"sh", "-c", "foo", forged},
		},
		"empty environment": {
			args: []string{"ls"}, envFound: true,
		},
		"empty assignment": {
			args: []string{"env", requestIdEnv + "=", "ls"}, env: uid, envFound: true,
			want: uid,
		},
		"no request": {
			args: []string{"nginx: master process nginx -g daemon off;"},
		},
		"no arguments": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, found := execRequestUID(tc.args, func() (string, bool) {
				return tc.env, tc.envFound
			})
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.want != "", found)
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
	mock.CmdlineForPIDReturns(
		"env "+requestIdEnv+"=first-request first",
		[]string{"env", requestIdEnv + "=first-request", "first"},
		nil,
	)

	first, err := GetProcessInfo(pid, "/bin/first", &uid, nil, cache, mock, nil)
	require.NoError(t, err)
	require.Equal(t, "env "+requestIdEnv+"=first-request first", first.CmdLine)
	require.Equal(t, "first-request", *first.ExecRequestId)
	require.Equal(t, "/bin/first", first.Executable)
	require.Equal(t, &uid, first.Uid)

	// Cached for the same process, with the details of the audit line.
	again, err := GetProcessInfo(pid, "/bin/exec", nil, nil, cache, mock, nil)
	require.NoError(t, err)
	require.Equal(t, first.CmdLine, again.CmdLine)
	require.Equal(t, "/bin/exec", again.Executable)
	require.Nil(t, again.Uid)
	require.Equal(t, 1, mock.CmdlineForPIDCallCount())

	// Another process with the PID.
	mock.ProcessStartTimeReturns(time.Minute, nil)
	mock.CmdlineForPIDReturns("second", []string{"second"}, nil)

	second, err := GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock, nil)
	require.NoError(t, err, "a process without request ID is no failure")
	require.Equal(t, "second", second.CmdLine)
	require.Nil(t, second.ExecRequestId)

	// Lines read after it exited are its own.
	mock.ProcessStartTimeReturns(0, os.ErrNotExist)
	mock.CmdlineForPIDReturns("", nil, os.ErrNotExist)

	gone, err := GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock, nil)
	require.NoError(t, err)
	require.Equal(t, "second", gone.CmdLine)

	// The cached info is never handed out itself.
	gone.CmdLine = "changed"

	again, err = GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock, nil)
	require.NoError(t, err)
	require.Equal(t, "second", again.CmdLine)

	// The details of an unknown process which is gone are not read.
	calls := mock.CmdlineForPIDCallCount()
	unknown, err := GetProcessInfo(pid+1, "/bin/unknown", nil, nil, cache, mock, nil)
	require.Error(t, err)
	require.Equal(t, pid+1, unknown.Pid)
	require.Equal(t, calls, mock.CmdlineForPIDCallCount())
}

// TestGetProcessInfoStartedLater asserts that the lines of a process which
// exited get the details of the process last seen with the PID, not the ones
// of a process which reused the PID after the line got logged.
func TestGetProcessInfoStartedLater(t *testing.T) {
	t.Parallel()

	const pid = 42

	cache := ttlcache.New(ttlcache.WithTTL[string, *types.ProcessInfo](time.Hour))
	mock := &enricherfakes.FakeImpl{}

	startedLater := func(started time.Duration) bool { return started > time.Minute }

	mock.ProcessStartTimeReturns(time.Second, nil)
	mock.CmdlineForPIDReturns("first", []string{"first"}, nil)

	first, err := GetProcessInfo(pid, "/bin/first", nil, nil, cache, mock, startedLater)
	require.NoError(t, err)
	require.Equal(t, "first", first.CmdLine)

	// The process exited and another one reused the PID after the line got
	// logged.
	mock.ProcessStartTimeReturns(time.Hour, nil)
	mock.CmdlineForPIDReturns("second", []string{"second"}, nil)

	again, err := GetProcessInfo(pid, "/bin/first", nil, nil, cache, mock, startedLater)
	require.NoError(t, err)
	require.Equal(t, "first", again.CmdLine)
	require.Equal(
		t,
		1,
		mock.CmdlineForPIDCallCount(),
		"the details of the new process are not read",
	)

	// The new process got cached by a line of its own, so it is no process
	// of an older line.
	second, err := GetProcessInfo(pid, "/bin/second", nil, nil, cache, mock, nil)
	require.NoError(t, err)
	require.Equal(t, "second", second.CmdLine)

	unknown, err := GetProcessInfo(pid, "/bin/first", nil, nil, cache, mock, startedLater)
	require.ErrorIs(t, err, errProcessStartedLater)
	require.Empty(t, unknown.CmdLine)
	require.Equal(t, pid, unknown.Pid)
	require.Equal(t, "/bin/first", unknown.Executable)
}
