//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2025 The Kubernetes Authors.

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

func getEventDataFileName() []byte {
	eventBytes := make([]byte, 8729)

	eventBytes[0] = 0x01 // Example PID byte
	eventBytes[1] = 0x00
	eventBytes[2] = 0x00
	eventBytes[3] = 0x00 // PID = 1

	eventBytes[8+4096] = 'f' // Start of filename
	eventBytes[8+4096+1] = 'o'
	eventBytes[8+4096+2] = 'o'
	eventBytes[8+4096+3] = '.'
	eventBytes[8+4096+4] = 't'
	eventBytes[8+4096+5] = 'x'
	eventBytes[8+4096+6] = 't'
	eventBytes[8+4096+7] = 0 // Null terminator

	return eventBytes
}

// Test Constants must match C definitions so that it can test the real code changes
const (
	MAX_ARGS         = 20
	MAX_ENV          = 50
	MAX_FILENAME_LEN = 128
	MAX_ARG_LEN      = 64
	MAX_ENV_LEN      = 64
	PATH_MAX         = 4096
)

func getArgsEnvData() []byte {
	const totalCStructSize = 8729

	eventBytes := make([]byte, totalCStructSize)

	eventBytes[0] = 0x01 // Example PID byte
	eventBytes[1] = 0x00
	eventBytes[2] = 0x00
	eventBytes[3] = 0x00 // PID = 1

	filenameOffset := 4 + 4 + 1 + 8 + PATH_MAX // = 4113

	copy(eventBytes[filenameOffset:], "myapp")

	eventBytes[filenameOffset+5] = 0 // Null terminator

	argsOffset := filenameOffset + MAX_FILENAME_LEN // = 4241
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

	envOffset := argsOffset + MAX_ARGS*MAX_ARG_LEN // = 5521

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

	argsLenOffset := envOffset + MAX_ENV*MAX_ENV_LEN // = 8721

	binary.LittleEndian.PutUint32(eventBytes[argsLenOffset:], uint32(len(sampleArgs)))

	envLenOffset := argsLenOffset + 4 // = 8725

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
			mock.GoArchReturns(validGoArch)
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
