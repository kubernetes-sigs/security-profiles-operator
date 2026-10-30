//go:build linux && !no_bpf

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

package bpfrecorder

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// newExecEvent returns an exec event of PID 1 with the arguments and the
// complete environment, laid out like the packed C struct in recorder.bpf.c.
func newExecEvent(args, env string) []byte {
	event := make([]byte, bpfExecEventDataOffset, bpfExecEventDataOffset+len(args)+len(env))

	binary.LittleEndian.PutUint32(event[0:], 1) // PID = 1
	event[16] = eventTypeExec

	//nolint:gosec // the lengths of test values
	setExecLens(event, uint32(len(args)), uint32(len(env)))

	return append(append(event, args...), env...)
}

// setExecLens overwrites the lengths of the arguments and the environment of
// an exec event.
func setExecLens(event []byte, argsLen, envLen uint32) []byte {
	binary.LittleEndian.PutUint32(event[bpfEventHeaderSize:], argsLen)
	binary.LittleEndian.PutUint32(event[bpfEventHeaderSize+4:], envLen)

	return event
}

// setExecGap overwrites the gap of the environment of an exec event.
func setExecGap(event []byte, gap uint32) []byte {
	binary.LittleEndian.PutUint32(event[bpfEventHeaderSize+8:], gap)

	return event
}

func TestBpfProcessCache_GetCmdLineAndRequestUID(t *testing.T) {
	t.Parallel()

	type args struct {
		pid        int
		eventBytes []byte
	}

	tests := []struct {
		name           string
		args           args
		wantCmdLine    string
		wantArgs       []string
		wantRequestUID string
		wantErr        bool
	}{
		{
			name: "exec without arguments",
			args: args{
				pid:        1,
				eventBytes: newExecEvent("", ""),
			},
			wantCmdLine: "",
			wantErr:     false,
		},
		{
			name: "Test with all event data args and env",
			args: args{
				pid: 1,
				eventBytes: newExecEvent(
					"arg1\x00--flag\x00value with spaces\x00last_arg\x00",
					"HOME=/root\x00SPO_EXEC_REQUEST_UID=dde426d5-123e-4296-b9ff-afd6eee83ee9\x00",
				),
			},
			wantCmdLine:    "arg1 --flag value with spaces last_arg",
			wantArgs:       []string{"arg1", "--flag", "value with spaces", "last_arg"},
			wantRequestUID: "dde426d5-123e-4296-b9ff-afd6eee83ee9",
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := NewBpfProcessCache(logr.Discard())
			mock := &bpfrecorderfakes.FakeImpl{}
			mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)

			b.recorder.impl = mock

			err := b.Load()

			if (err != nil) != tt.wantErr {
				t.Errorf("NewBpfProcessCache() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			if tt.args.eventBytes != nil {
				b.handleEvent(tt.args.eventBytes)
			}

			gotCmdLine, gotArgs, gotRequestUID, err := b.GetCmdLineAndRequestUID(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCmdLineAndRequestUID() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if strings.TrimSpace(gotCmdLine) != strings.TrimSpace(tt.wantCmdLine) {
				t.Errorf(
					"GetCmdLineAndRequestUID() gotCmdLine = %v, want %v",
					gotCmdLine,
					tt.wantCmdLine,
				)
			}

			if len(tt.wantArgs) > 0 && !reflect.DeepEqual(gotArgs, tt.wantArgs) {
				t.Errorf("GetCmdLineAndRequestUID() gotArgs = %q, want %q", gotArgs, tt.wantArgs)
			}

			if gotRequestUID != tt.wantRequestUID {
				t.Errorf(
					"GetCmdLineAndRequestUID() gotRequestUID = %q, want %q",
					gotRequestUID,
					tt.wantRequestUID,
				)
			}
		})
	}
}

// TestBpfProcessCacheIgnoresOtherEvents asserts that the container start event
// the exec hook also sends is not taken for a broken exec event.
func TestBpfProcessCacheIgnoresOtherEvents(t *testing.T) {
	t.Parallel()

	b := NewBpfProcessCache(logr.Discard())

	event := make([]byte, bpfEventHeaderSize)
	binary.LittleEndian.PutUint32(event[0:], 1)
	event[16] = eventTypeClearMntns

	b.handleEvent(event)

	cmdLine, _, requestUID, err := b.GetCmdLineAndRequestUID(1)
	require.Error(t, err)
	require.Empty(t, cmdLine)
	require.Empty(t, requestUID)
}

// TestBpfProcessCacheChecksStartTime asserts that the exec of a process is not
// handed out for another process which reused its PID.
func TestBpfProcessCacheChecksStartTime(t *testing.T) {
	t.Parallel()

	const startedAt = 5*time.Second + 3*time.Millisecond

	for _, tc := range []struct {
		name      string
		startedAt time.Duration
		running   time.Duration
		runErr    error
		wantErr   error
	}{
		{name: "same process", startedAt: startedAt, running: startedAt.Truncate(util.ProcessStartTimeTick)},
		{name: "process exited", startedAt: startedAt, runErr: errTest},
		{name: "unknown start", running: time.Hour},
		{
			name: "pid reused", startedAt: startedAt, running: time.Hour,
			wantErr: errProcessReplaced,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := NewBpfProcessCache(logr.Discard())

			event := newExecEvent("sh\x00", "SPO_EXEC_REQUEST_UID=r\x00")
			//nolint:gosec // a duration which is never negative
			binary.LittleEndian.PutUint64(event[17:25], uint64(tc.startedAt))
			b.handleEvent(event)

			var startTimeReads int

			b.startTime = func(int) (time.Duration, error) {
				startTimeReads++

				return tc.running, tc.runErr
			}

			cmdLine, args, requestUID, err := b.GetCmdLineAndRequestUID(1)

			// The process gets checked once for all of them.
			if tc.startedAt > 0 {
				require.Equal(t, 1, startTimeReads)
			}

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, "sh ", cmdLine)
			require.Equal(t, []string{"sh"}, args)
			require.Equal(t, "r", requestUID)
		})
	}
}

func TestBpfProcessCacheHandleEvent(t *testing.T) {
	t.Parallel()

	const (
		uid    = "dde426d5-123e-4296-b9ff-afd6eee83ee9"
		uidVar = "SPO_EXEC_REQUEST_UID=" + uid + "\x00"
	)

	// gapEvent returns an event whose environment has head and tail around
	// its gap.
	gapEvent := func(head, tail string) []byte {
		//nolint:gosec // the length of a test value
		return setExecGap(newExecEvent("sh\x00", head+tail), uint32(len(head)))
	}

	tests := []struct {
		name           string
		event          func() []byte
		wantCached     bool
		wantCmdLine    string
		wantRequestUID string
	}{
		{
			name: "request UID among other variables",
			event: func() []byte {
				return newExecEvent("sh\x00-c\x00", "A=b\x00"+uidVar+"C=d\x00")
			},
			wantCached:     true,
			wantCmdLine:    "sh -c ",
			wantRequestUID: uid,
		},
		{
			name: "truncated argument is kept",
			event: func() []byte {
				return newExecEvent("sh\x00-c\x00trunc", "")
			},
			wantCached:  true,
			wantCmdLine: "sh -c trunc ",
		},
		{
			name: "empty argument is kept",
			event: func() []byte {
				return newExecEvent("sh\x00\x00", "")
			},
			wantCached:  true,
			wantCmdLine: "sh  ",
		},
		{
			name: "empty request UID is none",
			event: func() []byte {
				return newExecEvent("sh\x00", "SPO_EXEC_REQUEST_UID=\x00")
			},
			wantCached:  true,
			wantCmdLine: "sh ",
		},
		{
			name: "request UID before the gap",
			event: func() []byte {
				return gapEvent("A=b\x00"+uidVar+"C=cut", "ut\x00D=e\x00")
			},
			wantCached:     true,
			wantCmdLine:    "sh ",
			wantRequestUID: uid,
		},
		{
			name: "request UID after the gap",
			event: func() []byte {
				return gapEvent("A=b\x00C=cut", "ut\x00D=e\x00"+uidVar)
			},
			wantCached:     true,
			wantCmdLine:    "sh ",
			wantRequestUID: uid,
		},
		{
			name: "request UID right after the gap",
			event: func() []byte {
				return gapEvent("A=b\x00C=cut", "\x00"+uidVar)
			},
			wantCached:     true,
			wantCmdLine:    "sh ",
			wantRequestUID: uid,
		},
		{
			name: "request UID cut before the gap",
			event: func() []byte {
				return gapEvent("A=b\x00"+uidVar[:30], "ut\x00D=e\x00")
			},
			wantCached:  true,
			wantCmdLine: "sh ",
		},
		{
			name: "request UID cut after the gap",
			event: func() []byte {
				return gapEvent("A=b\x00", uidVar[10:]+"D=e\x00")
			},
			wantCached:  true,
			wantCmdLine: "sh ",
		},
		{
			name: "lengths beyond the event are dropped",
			event: func() []byte {
				return setExecLens(newExecEvent("sh\x00", "K=v\x00"), 4, 5)
			},
		},
		{
			name: "short event is dropped",
			event: func() []byte {
				return newExecEvent("", "")[:bpfExecEventDataOffset-1]
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := NewBpfProcessCache(logr.Discard())
			b.handleEvent(tc.event())

			cmdLine, args, requestUID, err := b.GetCmdLineAndRequestUID(1)
			if !tc.wantCached {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantCmdLine, cmdLine)
			require.Equal(t, tc.wantCmdLine, strings.Join(args, " ")+" ")
			require.Equal(t, tc.wantRequestUID, requestUID)
		})
	}
}

// TestBpfProcessCacheLoadClosesModuleOnError asserts that a module which got
// created is unloaded again if loading fails later on.
func TestBpfProcessCacheLoadClosesModuleOnError(t *testing.T) {
	t.Parallel()

	b := NewBpfProcessCache(logr.Discard())
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	mock.BPFLoadObjectReturns(errTest)
	b.recorder.impl = mock

	require.ErrorIs(t, b.Load(), errTest)
	require.Equal(t, 1, mock.CloseModuleCallCount())
}

// TestBpfProcessCacheLoadShrinksUnusedMaps asserts that the maps only the
// recorder fills are shrunk before the object gets loaded.
func TestBpfProcessCacheLoadShrinksUnusedMaps(t *testing.T) {
	t.Parallel()

	b := NewBpfProcessCache(logr.Discard())
	mock := &bpfrecorderfakes.FakeImpl{}
	mock.NewModuleFromBufferArgsReturns(&libbpfgo.Module{}, nil)
	b.recorder.impl = mock

	require.NoError(t, b.Load())

	require.Equal(t, len(procCacheUnusedMaps), mock.SetMaxEntriesCallCount())

	for i := range mock.SetMaxEntriesCallCount() {
		_, maxEntries := mock.SetMaxEntriesArgsForCall(i)
		require.Equal(t, uint32(1), maxEntries)
	}

	for i, name := range procCacheUnusedMaps {
		_, got := mock.GetMapArgsForCall(i)
		require.Equal(t, name, got)
	}

	b.Close()
}
