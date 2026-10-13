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

// newExecEvent returns an exec event with the header set, laid out like the
// packed C struct in recorder.bpf.c.
func newExecEvent() []byte {
	eventBytes := make([]byte, bpfExecEventSize)

	binary.LittleEndian.PutUint32(eventBytes[0:], 1) // PID = 1
	eventBytes[16] = eventTypeExecveEnter

	return eventBytes
}

func getEventDataFileName() []byte {
	eventBytes := newExecEvent()

	copy(eventBytes[bpfEventHeaderSize:], "foo.txt\x00")

	return eventBytes
}

// Test Constants must match C definitions so that it can test the real code changes.
const (
	MAX_ARGS         = 20
	MAX_ENV          = 50
	MAX_FILENAME_LEN = 128
	MAX_ARG_LEN      = 64
	MAX_ENV_LEN      = 64
)

func getArgsEnvData() []byte {
	eventBytes := newExecEvent()

	filenameOffset := bpfEventHeaderSize

	copy(eventBytes[filenameOffset:], "myapp")

	eventBytes[filenameOffset+5] = 0 // Null terminator

	argsOffset := filenameOffset + MAX_FILENAME_LEN
	sampleArgs := []string{"arg1", "--flag", "value with spaces", "last_arg"}

	for i, arg := range sampleArgs {
		if i >= MAX_ARGS {
			break
		}

		copy(eventBytes[argsOffset+i*MAX_ARG_LEN:], arg)

		if len(arg) < MAX_ARG_LEN {
			eventBytes[argsOffset+i*MAX_ARG_LEN+len(arg)] = 0 // Null terminator
		}
	}

	envOffset := argsOffset + MAX_ARGS*MAX_ARG_LEN

	sampleEnv := []string{"HOME=/root", "SPO_EXEC_REQUEST_UID=dde426d5-123e-4296-b9ff-afd6eee83ee9"}
	for i, env := range sampleEnv {
		if i >= MAX_ENV {
			break
		}

		copy(eventBytes[envOffset+i*MAX_ENV_LEN:], env)

		if len(env) < MAX_ENV_LEN {
			eventBytes[envOffset+i*MAX_ENV_LEN+len(env)] = 0 // Null terminator
		}
	}

	argsLenOffset := envOffset + MAX_ENV*MAX_ENV_LEN

	//nolint:gosec // a few test values
	binary.LittleEndian.PutUint32(eventBytes[argsLenOffset:], uint32(len(sampleArgs)))

	envLenOffset := argsLenOffset + 4

	//nolint:gosec // a few test values
	binary.LittleEndian.PutUint32(eventBytes[envLenOffset:], uint32(len(sampleEnv)))

	return eventBytes
}

func TestBpfProcessCache_GetCmdLineEnv(t *testing.T) {
	t.Parallel()

	type args struct {
		pid        int
		eventBytes []byte
	}

	tests := []struct {
		name        string
		args        args
		wantCmdLine string
		wantEnv     map[string]string
		wantErr     bool
	}{
		{
			name: "Basic Test with event data filename",
			args: args{
				pid:        1,
				eventBytes: getEventDataFileName(),
			},
			wantCmdLine: "",
			wantErr:     false,
		},
		{
			name: "Test with all event data args and env",
			args: args{
				pid:        1,
				eventBytes: getArgsEnvData(),
			},
			wantCmdLine: "arg1 --flag value with spaces last_arg",
			wantEnv: map[string]string{
				"HOME":                 "/root",
				"SPO_EXEC_REQUEST_UID": "dde426d5-123e-4296-b9ff-afd6eee83ee9",
			},
			wantErr: false,
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

			gotCmdLine, gotEnv, err := b.GetCmdLineAndEnv(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCmdLineAndEnv() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if strings.TrimSpace(gotCmdLine) != strings.TrimSpace(tt.wantCmdLine) {
				t.Errorf("GetCmdLineAndEnv() gotCmdLine = %v, want %v", gotCmdLine, tt.wantCmdLine)
			}

			if len(gotEnv) != len(tt.wantEnv) {
				t.Errorf(
					"GetCmdLineAndEnv() gotEnv len = %v, want len %v",
					len(gotEnv),
					len(tt.wantEnv),
				)
			}

			if len(gotEnv) == 0 {
				return
			}

			if !reflect.DeepEqual(gotEnv, tt.wantEnv) {
				t.Errorf("GetCmdLineAndEnv() gotEnv = %v, want %v", gotEnv, tt.wantEnv)
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

	_, _, err := b.GetCmdLineAndEnv(1)
	require.Error(t, err)
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

			event := newExecEvent()
			//nolint:gosec // a duration which is never negative
			binary.LittleEndian.PutUint64(event[17:25], uint64(tc.startedAt))
			putExecSlot(argSlot(event, 0), "sh", "")
			putExecSlot(envSlot(event, 0), "K=v", "")
			setExecLens(event, 1, 1)
			b.handleEvent(event)

			var startTimeReads int

			b.startTime = func(int) (time.Duration, error) {
				startTimeReads++

				return tc.running, tc.runErr
			}

			cmdLine, env, err := b.GetCmdLineAndEnv(1)

			// The process gets checked once for both.
			if tc.startedAt > 0 {
				require.Equal(t, 1, startTimeReads)
			}

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, "sh ", cmdLine)
			require.Equal(t, map[string]string{"K": "v"}, env)
		})
	}
}

// putExecSlot writes value into a slot of the args or env array of an exec
// event, followed by a terminator and stale bytes, the way a reused ring
// buffer slot looks.
func putExecSlot(slot []byte, value, stale string) {
	for j := range slot {
		slot[j] = 'X'
	}

	n := copy(slot, value)
	slot[n] = 0
	copy(slot[n+1:], stale)
}

func argSlot(event []byte, i int) []byte {
	offset := bpfEventHeaderSize + maxFileNameLen + i*maxArgLen

	return event[offset : offset+maxArgLen]
}

func envSlot(event []byte, i int) []byte {
	offset := bpfEventHeaderSize + maxFileNameLen + maxArgs*maxArgLen + i*maxEnvLen

	return event[offset : offset+maxEnvLen]
}

func setExecLens(event []byte, argsLen, envLen uint32) {
	lenOffset := bpfEventHeaderSize + maxFileNameLen + maxArgs*maxArgLen + maxEnv*maxEnvLen
	binary.LittleEndian.PutUint32(event[lenOffset:], argsLen)
	binary.LittleEndian.PutUint32(event[lenOffset+4:], envLen)
}

func TestBpfProcessCacheHandleEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		event       func() []byte
		wantCached  bool
		wantCmdLine string
		wantEnv     map[string]string
	}{
		{
			name: "stale bytes after the terminator are ignored",
			event: func() []byte {
				event := newExecEvent()
				copy(event[bpfEventHeaderSize:], "/bin/sh\x00/usr/bin/stale")
				putExecSlot(argSlot(event, 0), "sh", "stale-arg")
				putExecSlot(argSlot(event, 1), "-c", "")
				putExecSlot(envSlot(event, 0), "A=b", "C=stale")
				putExecSlot(envSlot(event, 1), `"Q"="v"`, "=x")
				setExecLens(event, 2, 2)

				return event
			},
			wantCached:  true,
			wantCmdLine: "sh -c ",
			wantEnv:     map[string]string{"A": "b", "Q": "v"},
		},
		{
			name: "slot without terminator keeps all bytes",
			event: func() []byte {
				event := newExecEvent()
				copy(argSlot(event, 0), strings.Repeat("a", maxArgLen))
				setExecLens(event, 1, 0)

				return event
			},
			wantCached:  true,
			wantCmdLine: strings.Repeat("a", maxArgLen) + " ",
			wantEnv:     map[string]string{},
		},
		{
			name: "env entry without separator is skipped",
			event: func() []byte {
				event := newExecEvent()
				putExecSlot(envSlot(event, 0), "NOVALUE", "=stale")
				setExecLens(event, 0, 1)

				return event
			},
			wantCached: true,
			wantEnv:    map[string]string{},
		},
		{
			name: "lengths beyond the arrays are clamped",
			event: func() []byte {
				event := newExecEvent()
				for i := range maxArgs {
					putExecSlot(argSlot(event, i), "a", "stale")
				}

				for i := range maxEnv {
					putExecSlot(envSlot(event, i), "K=v", "stale")
				}

				setExecLens(event, 1000, 1000)

				return event
			},
			wantCached:  true,
			wantCmdLine: strings.Repeat("a ", maxArgs),
			wantEnv:     map[string]string{"K": "v"},
		},
		{
			name: "short event is dropped",
			event: func() []byte {
				return newExecEvent()[:bpfExecEventSize-1]
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := NewBpfProcessCache(logr.Discard())
			b.handleEvent(tc.event())

			cmdLine, env, err := b.GetCmdLineAndEnv(1)
			if !tc.wantCached {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantCmdLine, cmdLine)
			require.Equal(t, tc.wantEnv, env)
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
