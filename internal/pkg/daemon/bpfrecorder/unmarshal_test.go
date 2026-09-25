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

func TestBpfEventUnmarshalMatchesBinaryRead(t *testing.T) {
	t.Parallel()

	raw := randomBytes(t, bpfEventSize)

	var want bpfEvent

	require.NoError(t, binary.Read(bytes.NewReader(raw), binary.LittleEndian, &want))

	var got bpfEvent

	require.True(t, got.unmarshal(raw))
	require.Equal(t, want, got)
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
	raw[16] = uint8(eventTypeAppArmorFile)
	binary.LittleEndian.PutUint64(raw[17:], flagRead)
	raw = append(raw, "/a/b\x00"...)

	// A previous, longer path must not shine through.
	var event bpfEvent

	copy(event.Data[:], "/previous/long/path")

	require.True(t, event.unmarshal(raw))
	require.Equal(t, uint32(42), event.Pid)
	require.Equal(t, uint32(0x1010), event.Mntns)
	require.Equal(t, uint64(0xdeadbeef), event.Key)
	require.Equal(t, uint8(eventTypeAppArmorFile), event.Type)
	require.Equal(t, flagRead, event.Flags)
	require.Equal(t, "/a/b", fileDataToString(&event.Data))
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
		var event bpfEvent

		b.ReportAllocs()

		for range b.N {
			if err := binary.Read(
				bytes.NewReader(raw), binary.LittleEndian, &event,
			); err != nil {
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
