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
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// The manual unmarshalers replace binary.Read for performance. These tests pin
// them to binary.Read's behaviour so the two cannot drift.

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()

	//nolint:gosec // test data does not need a cryptographic source
	rng := rand.New(rand.NewSource(1))
	raw := make([]byte, n)

	_, err := rng.Read(raw)
	require.NoError(t, err)

	return raw
}

// bpfEventHeader is the wire layout of the event header, to decode it with
// binary.Read.
type bpfEventHeader struct {
	Pid   uint32
	Mntns uint32
	Key   uint64
	Type  uint8
	Flags uint64
}

func TestBpfEventUnmarshalMatchesBinaryRead(t *testing.T) {
	t.Parallel()

	raw := randomBytes(t, bpfEventSize)

	var want bpfEventHeader

	require.NoError(t, binary.Read(bytes.NewReader(raw), binary.LittleEndian, &want))

	var got bpfEvent

	require.True(t, got.unmarshal(raw))
	require.Equal(t, want, bpfEventHeader{
		Pid: got.Pid, Mntns: got.Mntns, Key: got.Key, Type: got.Type, Flags: got.Flags,
	})
	require.Equal(t, raw[bpfEventHeaderSize:], got.Data)
}

func TestBpfEventUnmarshalRejectsShortInput(t *testing.T) {
	t.Parallel()

	var event bpfEvent

	require.False(t, event.unmarshal(nil))
	require.False(t, event.unmarshal(randomBytes(t, bpfEventHeaderSize-1)))
	require.True(t, event.unmarshal(randomBytes(t, bpfEventHeaderSize)))
	require.True(t, event.unmarshal(randomBytes(t, bpfEventSize)))
}

// Events without data and file events only carry as much data as they need.
func TestBpfEventUnmarshalVariableSize(t *testing.T) {
	t.Parallel()

	raw := make([]byte, bpfEventHeaderSize, bpfEventHeaderSize+8)
	binary.LittleEndian.PutUint32(raw[0:], 42)
	binary.LittleEndian.PutUint32(raw[4:], 0x1010)
	binary.LittleEndian.PutUint64(raw[8:], 0xdeadbeef)
	raw[16] = eventTypeAppArmorFile
	binary.LittleEndian.PutUint64(raw[17:], flagRead)
	raw = append(raw, "/a/b\x00"...)

	// A previous, longer path must not shine through.
	event := bpfEvent{Data: []byte("/previous/long/path\x00")}

	require.True(t, event.unmarshal(raw))
	require.Equal(t, uint32(42), event.Pid)
	require.Equal(t, uint32(0x1010), event.Mntns)
	require.Equal(t, uint64(0xdeadbeef), event.Key)
	require.Equal(t, eventTypeAppArmorFile, event.Type)
	require.Equal(t, flagRead, event.Flags)
	require.Equal(t, "/a/b", string(fileData(event.Data)))

	// The data references the raw bytes instead of copying them.
	require.Same(t, &raw[bpfEventHeaderSize], &event.Data[0])
}

func TestFileDataToString(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"terminated":     {data: []byte("/etc/passwd\x00"), want: "/etc/passwd"},
		"directory":      {data: []byte("/etc/\x00"), want: "/etc/"},
		"not terminated": {data: []byte("/etc/passwd"), want: "/etc/passwd"},
		"empty":          {data: nil, want: ""},
		"only NUL":       {data: []byte{0}, want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, string(fileData(tc.data)))
		})
	}
}

func TestBpfExecEventUnmarshalMatchesBinaryRead(t *testing.T) {
	t.Parallel()

	raw := randomBytes(t, bpfExecEventSize)

	var want bpfExecEvent

	require.NoError(t, binary.Read(bytes.NewReader(raw), binary.LittleEndian, &want))

	var got bpfExecEvent

	require.True(t, got.unmarshal(raw))
	require.Equal(t, want, got)
}

func TestBpfExecEventUnmarshalRejectsShortInput(t *testing.T) {
	t.Parallel()

	var event bpfExecEvent

	require.False(t, event.unmarshal(randomBytes(t, bpfExecEventSize-1)))
	require.True(t, event.unmarshal(randomBytes(t, bpfExecEventSize)))
}

func BenchmarkBpfEventDecode(b *testing.B) {
	raw := make([]byte, bpfEventSize)

	b.Run("binary.Read", func(b *testing.B) {
		var header bpfEventHeader

		data := make([]byte, pathMax)

		b.ReportAllocs()

		for range b.N {
			reader := bytes.NewReader(raw)
			if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
				b.Fatal(err)
			}

			if _, err := reader.Read(data); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("unmarshal", func(b *testing.B) {
		var event bpfEvent

		b.ReportAllocs()

		for range b.N {
			_ = event.unmarshal(raw)
		}
	})
}
