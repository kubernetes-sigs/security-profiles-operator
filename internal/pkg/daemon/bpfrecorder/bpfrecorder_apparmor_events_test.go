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
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
)

// These handlers turn raw BPF events into the rules a generated AppArmor
// profile grants, so a mistake here silently produces an over- or
// under-permissive profile.

const testMntns uint32 = 0x1010

func newTestAppArmorRecorder() *AppArmorRecorder {
	return newAppArmorRecorder(logr.Discard(), "test")
}

func fileEvent(mntns uint32, flags uint64, path string) *bpfEvent {
	e := &bpfEvent{
		Pid:   1,
		Mntns: mntns,
		Type:  uint8(eventTypeAppArmorFile),
		Flags: flags,
	}
	copy(e.Data[:], path)

	return e
}

func TestHandleFileEvent(t *testing.T) {
	t.Parallel()

	t.Run("records the access flags", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testMntns, flagRead, "/etc/passwd"))

		access := sut.recordedFiles[mntnsID(testMntns)]["/etc/passwd"]
		require.NotNil(t, access)
		require.True(t, access.read)
		require.False(t, access.write)
		require.False(t, access.exec)
	})

	t.Run("accumulates flags across events for the same path", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testMntns, flagRead, "/data/file"))
		sut.handleFileEvent(fileEvent(testMntns, flagWrite, "/data/file"))
		sut.handleFileEvent(fileEvent(testMntns, flagExec, "/data/file"))

		access := sut.recordedFiles[mntnsID(testMntns)]["/data/file"]
		require.NotNil(t, access)
		require.True(t, access.read)
		require.True(t, access.write)
		require.True(t, access.exec)
	})

	t.Run("keeps mount namespaces apart", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagRead, "/one"))
		sut.handleFileEvent(fileEvent(2, flagWrite, "/two"))

		require.Contains(t, sut.recordedFiles[mntnsID(1)], "/one")
		require.NotContains(t, sut.recordedFiles[mntnsID(1)], "/two")
		require.Contains(t, sut.recordedFiles[mntnsID(2)], "/two")
	})

	t.Run("excluded files are not recorded", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		// Container runtime paths are noise from starting the container, not
		// something the workload itself needs.
		sut.handleFileEvent(fileEvent(testMntns, flagRead, "/usr/bin/runc"))

		require.Empty(t, sut.recordedFiles[mntnsID(testMntns)])
	})

	t.Run("variance in the path is normalised", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testMntns, flagRead, "/proc/1234/cmdline"))

		for path := range sut.recordedFiles[mntnsID(testMntns)] {
			require.NotContains(t, path, "1234",
				"a concrete pid must not end up in the profile")
		}
	})

	t.Run("stops tracking paths past the limit", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		for i := range maxTrackedPaths + 10 {
			sut.handleFileEvent(fileEvent(testMntns, flagRead, fmt.Sprintf("/f/%d", i)))
		}

		require.Len(t, sut.recordedFiles[mntnsID(testMntns)], maxTrackedPaths)
		require.True(t, sut.maxPathsWarned[mntnsID(testMntns)])
	})

	t.Run("stops tracking mount namespaces past the limit", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		for i := range maxTrackedMntns + 10 {
			sut.handleFileEvent(fileEvent(uint32(i), flagRead, "/f"))
		}

		require.Len(t, sut.recordedFiles, maxTrackedMntns)
		require.True(t, sut.maxMntnsWarned)
	})
}

func TestHandleSocketEvent(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		flags uint64
		want  BpfAppArmorSocketTypes
	}{
		"raw":                                 {flags: sockRaw, want: BpfAppArmorSocketTypes{UseRaw: true}},
		"stream":                              {flags: sockStream, want: BpfAppArmorSocketTypes{UseTCP: true}},
		"dgram":                               {flags: sockDgram, want: BpfAppArmorSocketTypes{UseUDP: true}},
		"unknown socket type records nothing": {flags: 0, want: BpfAppArmorSocketTypes{}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut := newTestAppArmorRecorder()
			sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: tc.flags})

			require.Equal(t, &tc.want, sut.recordedSocketsUse[mntnsID(testMntns)])
		})
	}

	t.Run("socket types accumulate", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: sockStream})
		sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: sockDgram})

		require.Equal(t,
			&BpfAppArmorSocketTypes{UseTCP: true, UseUDP: true},
			sut.recordedSocketsUse[mntnsID(testMntns)])
	})

	t.Run("the flags are masked to the socket type", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		// High bits carry unrelated information and must not change the type.
		sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: 0xFFF0 | sockDgram})

		require.Equal(t,
			&BpfAppArmorSocketTypes{UseUDP: true},
			sut.recordedSocketsUse[mntnsID(testMntns)])
	})
}

func TestHandleCapabilityEvent(t *testing.T) {
	t.Parallel()

	t.Run("records a capability once", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 1})
		sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 1})

		require.Equal(t, []int{1}, sut.recordedCapabilities[mntnsID(testMntns)])
	})

	t.Run("records distinct capabilities", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 1})
		sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 7})

		require.ElementsMatch(t, []int{1, 7}, sut.recordedCapabilities[mntnsID(testMntns)])
	})
}

// clearMntns exists so that permissions needed only during container setup do
// not leak into the recorded profile.
func TestClearMntns(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()
	sut.handleFileEvent(fileEvent(testMntns, flagRead, "/setup"))
	sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: sockStream})
	sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 1})

	// An unrelated namespace must survive.
	sut.handleFileEvent(fileEvent(2, flagRead, "/keep"))

	sut.clearMntns(&bpfEvent{Mntns: testMntns})

	require.NotContains(t, sut.recordedFiles, mntnsID(testMntns))
	require.NotContains(t, sut.recordedSocketsUse, mntnsID(testMntns))
	require.NotContains(t, sut.recordedCapabilities, mntnsID(testMntns))
	require.Contains(t, sut.recordedFiles, mntnsID(2))
}

// GetAppArmorProcessed turns the recorded events into the profile contents and
// consumes them, so a second call must not report the same access again.
func TestGetAppArmorProcessed(t *testing.T) {
	t.Parallel()

	t.Run("classifies file access", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testMntns, flagRead, "/read/only"))
		sut.handleFileEvent(fileEvent(testMntns, flagWrite, "/write/only"))
		sut.handleFileEvent(fileEvent(testMntns, flagRead|flagWrite, "/read/write"))
		sut.handleFileEvent(fileEvent(testMntns, flagSpawn, "/bin/spawned"))

		got := sut.GetAppArmorProcessed(testMntns)

		require.Contains(t, got.FileProcessed.ReadOnlyPaths, "/read/only")
		require.Contains(t, got.FileProcessed.WriteOnlyPaths, "/write/only")
		require.Contains(t, got.FileProcessed.ReadWritePaths, "/read/write")
		require.Contains(t, got.FileProcessed.AllowedExecutables, "/bin/spawned")
	})

	t.Run("reports sockets and capabilities", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: sockRaw})
		sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 1})

		got := sut.GetAppArmorProcessed(testMntns)

		require.True(t, got.Socket.UseRaw)
		require.NotEmpty(t, got.Capabilities)
	})

	t.Run("is consumed after being read", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleSocketEvent(&bpfEvent{Mntns: testMntns, Flags: sockStream})
		sut.handleCapabilityEvent(&bpfEvent{Mntns: testMntns, Flags: 1})

		require.True(t, sut.GetAppArmorProcessed(testMntns).Socket.UseTCP)

		second := sut.GetAppArmorProcessed(testMntns)
		require.Equal(t, BpfAppArmorSocketTypes{}, second.Socket)
		require.Empty(t, second.Capabilities)
	})

	t.Run("an unknown mount namespace yields nothing", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		got := sut.GetAppArmorProcessed(9999)

		require.Empty(t, got.FileProcessed.ReadOnlyPaths)
		require.Equal(t, BpfAppArmorSocketTypes{}, got.Socket)
		require.Empty(t, got.Capabilities)
	})
}
