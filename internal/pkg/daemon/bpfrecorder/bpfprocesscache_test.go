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

	"github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
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

	binary.LittleEndian.PutUint32(eventBytes[argsLenOffset:], uint32(len(sampleArgs)))

	envLenOffset := argsLenOffset + 4

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

			gotCmdLine, err := b.GetCmdLine(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCmdLine() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if strings.TrimSpace(gotCmdLine) != strings.TrimSpace(tt.wantCmdLine) {
				t.Errorf("GetCmdLine() gotCmdLine = %v, want %v", gotCmdLine, tt.wantCmdLine)
			}

			gotEnv, err := b.GetEnv(tt.args.pid)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEnv() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if len(gotEnv) != len(tt.wantEnv) {
				t.Errorf("GetEnv() gotEnv len = %v, want len %v", len(gotEnv), len(tt.wantEnv))
			}

			if len(gotEnv) == 0 {
				return
			}

			if !reflect.DeepEqual(gotEnv, tt.wantEnv) {
				t.Errorf("GetEnv() gotEnv = %v, want %v", gotEnv, tt.wantEnv)
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
	event[16] = byte(eventTypeClearMntns)

	b.handleEvent(event)

	_, err := b.GetCmdLine(1)
	require.Error(t, err)
}
