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
	"regexp"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
)

// These handlers turn raw BPF events into the rules a generated AppArmor
// profile grants, so a mistake here silently produces an over- or
// under-permissive profile.

const testKey uint64 = 0x1010

func newTestAppArmorRecorder() *AppArmorRecorder {
	return newAppArmorRecorder(logr.Discard(), "test")
}

func fileEvent(key, flags uint64, path string) *bpfEvent {
	e := &bpfEvent{
		Pid:   1,
		Key:   key,
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
		sut.handleFileEvent(fileEvent(testKey, flagRead, "/etc/passwd"))

		access := sut.recordedFiles[recordingKey(testKey)]["/etc/passwd"]
		require.NotNil(t, access)
		require.True(t, access.read)
		require.False(t, access.write)
		require.False(t, access.exec)
	})

	t.Run("accumulates flags across events for the same path", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testKey, flagRead, "/data/file"))
		sut.handleFileEvent(fileEvent(testKey, flagWrite, "/data/file"))
		sut.handleFileEvent(fileEvent(testKey, flagExec, "/data/file"))

		access := sut.recordedFiles[recordingKey(testKey)]["/data/file"]
		require.NotNil(t, access)
		require.True(t, access.read)
		require.True(t, access.write)
		require.True(t, access.exec)
	})

	t.Run("keeps keys apart", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagRead, "/one"))
		sut.handleFileEvent(fileEvent(2, flagWrite, "/two"))

		require.Contains(t, sut.recordedFiles[recordingKey(1)], "/one")
		require.NotContains(t, sut.recordedFiles[recordingKey(1)], "/two")
		require.Contains(t, sut.recordedFiles[recordingKey(2)], "/two")
	})

	t.Run("excluded files are not recorded", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		// Container runtime paths are noise from starting the container, not
		// something the workload itself needs.
		sut.handleFileEvent(fileEvent(testKey, flagRead, "/usr/bin/runc"))

		require.Empty(t, sut.recordedFiles[recordingKey(testKey)])
	})

	t.Run("variance in the path is normalised", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testKey, flagRead, "/proc/1234/cmdline"))

		for path := range sut.recordedFiles[recordingKey(testKey)] {
			require.NotContains(t, path, "1234",
				"a concrete pid must not end up in the profile")
		}
	})

	t.Run("stops tracking paths past the limit", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		for i := range maxTrackedPaths + 10 {
			sut.handleFileEvent(fileEvent(testKey, flagRead, fmt.Sprintf("/f/%d", i)))
		}

		require.Len(t, sut.recordedFiles[recordingKey(testKey)], maxTrackedPaths)
		require.True(t, sut.maxPathsWarned[recordingKey(testKey)])
	})

	t.Run("stops tracking keys past the limit", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		for i := range maxTrackedKeys + 10 {
			sut.handleFileEvent(fileEvent(uint64(i), flagRead, "/f"))
		}

		require.Len(t, sut.recordedFiles, maxTrackedKeys)
		require.True(t, sut.maxKeysWarned)
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
			sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: tc.flags})

			require.Equal(t, &tc.want, sut.recordedSocketsUse[recordingKey(testKey)])
		})
	}

	t.Run("socket types accumulate", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: sockStream})
		sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: sockDgram})

		require.Equal(t,
			&BpfAppArmorSocketTypes{UseTCP: true, UseUDP: true},
			sut.recordedSocketsUse[recordingKey(testKey)])
	})

	t.Run("the flags are masked to the socket type", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		// High bits carry unrelated information and must not change the type.
		sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: 0xFFF0 | sockDgram})

		require.Equal(t,
			&BpfAppArmorSocketTypes{UseUDP: true},
			sut.recordedSocketsUse[recordingKey(testKey)])
	})
}

func TestHandleCapabilityEvent(t *testing.T) {
	t.Parallel()

	t.Run("records a capability once", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 1})
		sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 1})

		require.Equal(t, []int{1}, sut.recordedCapabilities[recordingKey(testKey)])
	})

	t.Run("records distinct capabilities", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 1})
		sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 7})

		require.ElementsMatch(t, []int{1, 7}, sut.recordedCapabilities[recordingKey(testKey)])
	})
}

// clearKey exists so that permissions needed only during container setup do
// not leak into the recorded profile.
func TestClearKey(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()
	sut.handleFileEvent(fileEvent(testKey, flagRead, "/setup"))
	sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: sockStream})
	sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 1})

	// An unrelated key must survive.
	sut.handleFileEvent(fileEvent(2, flagRead, "/keep"))

	sut.clearKey(&bpfEvent{Key: testKey})

	require.NotContains(t, sut.recordedFiles, recordingKey(testKey))
	require.NotContains(t, sut.recordedSocketsUse, recordingKey(testKey))
	require.NotContains(t, sut.recordedCapabilities, recordingKey(testKey))
	require.Contains(t, sut.recordedFiles, recordingKey(2))
}

// GetAppArmorProcessed turns the recorded events into the profile contents. It
// keeps them until they are cleared, so that storing the profile can be
// retried.
func TestGetAppArmorProcessed(t *testing.T) {
	t.Parallel()

	keys := []uint64{testKey}

	t.Run("classifies file access", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(testKey, flagRead, "/read/only"))
		sut.handleFileEvent(fileEvent(testKey, flagWrite, "/write/only"))
		sut.handleFileEvent(fileEvent(testKey, flagRead|flagWrite, "/read/write"))
		sut.handleFileEvent(fileEvent(testKey, flagSpawn, "/bin/spawned"))

		got, ok := sut.GetAppArmorProcessed(keys)
		require.True(t, ok)

		require.Contains(t, got.FileProcessed.ReadOnlyPaths, "/read/only")
		require.Contains(t, got.FileProcessed.WriteOnlyPaths, "/write/only")
		require.Contains(t, got.FileProcessed.ReadWritePaths, "/read/write")
		require.Contains(t, got.FileProcessed.AllowedExecutables, "/bin/spawned")
	})

	t.Run("adds only the access the abstractions do not allow", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		// Reading is allowed by the base abstraction, writing is not.
		sut.handleFileEvent(fileEvent(testKey, flagRead|flagWrite, "/etc/localtime"))
		// Writing is allowed by the base abstraction, reading is not.
		sut.handleFileEvent(fileEvent(testKey, flagRead|flagWrite, "/dev/log"))
		// Both are allowed.
		sut.handleFileEvent(fileEvent(testKey, flagRead, "/etc/ld.so.cache"))

		got, ok := sut.GetAppArmorProcessed(keys)
		require.True(t, ok)

		require.Equal(t, []string{"/etc/localtime"}, got.FileProcessed.WriteOnlyPaths)
		require.Equal(t, []string{"/dev/log"}, got.FileProcessed.ReadOnlyPaths)
		require.Empty(t, got.FileProcessed.ReadWritePaths)
	})

	t.Run("reports sockets and capabilities", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: sockRaw})
		sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 1})

		got, ok := sut.GetAppArmorProcessed(keys)
		require.True(t, ok)

		require.True(t, got.Socket.UseRaw)
		require.NotEmpty(t, got.Capabilities)
	})

	t.Run("is kept until cleared", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleSocketEvent(&bpfEvent{Key: testKey, Flags: sockStream})
		sut.handleCapabilityEvent(&bpfEvent{Key: testKey, Flags: 1})

		first, ok := sut.GetAppArmorProcessed(keys)
		require.True(t, ok)
		require.True(t, first.Socket.UseTCP)

		second, ok := sut.GetAppArmorProcessed(keys)
		require.True(t, ok)
		require.Equal(t, first, second)

		sut.Clear(keys)

		cleared, ok := sut.GetAppArmorProcessed(keys)
		require.False(t, ok)
		require.Equal(t, BpfAppArmorSocketTypes{}, cleared.Socket)
		require.Empty(t, cleared.Capabilities)
	})

	t.Run("merges all keys of a container", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagRead, "/data/file"))
		sut.handleFileEvent(fileEvent(2, flagWrite, "/data/file"))
		sut.handleSocketEvent(&bpfEvent{Key: 1, Flags: sockStream})
		sut.handleSocketEvent(&bpfEvent{Key: 2, Flags: sockDgram})
		sut.handleCapabilityEvent(&bpfEvent{Key: 1, Flags: 1})
		sut.handleCapabilityEvent(&bpfEvent{Key: 2, Flags: 1})
		sut.handleCapabilityEvent(&bpfEvent{Key: 2, Flags: 7})
		sut.handleFileEvent(fileEvent(3, flagRead, "/other"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1, 2})
		require.True(t, ok)

		require.Equal(t, []string{"/data/file"}, got.FileProcessed.ReadWritePaths)
		require.NotContains(t, got.FileProcessed.ReadOnlyPaths, "/other")
		require.True(t, got.Socket.UseTCP)
		require.True(t, got.Socket.UseUDP)
		require.Equal(t, []string{"dac_override", "setuid"}, got.Capabilities)
	})

	t.Run("an unknown key yields nothing", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		got, ok := sut.GetAppArmorProcessed([]uint64{9999})

		require.False(t, ok)
		require.Empty(t, got.FileProcessed.ReadOnlyPaths)
		require.Equal(t, BpfAppArmorSocketTypes{}, got.Socket)
		require.Empty(t, got.Capabilities)
	})
}

func TestSanitizeFilePath(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]string{
		"/etc/passwd":                       "/etc/passwd",
		"/opt/my app/v1.2+3/run_app":        "/opt/my app/v1.2+3/run_app",
		"/sys/bus/pci/devices/0000:00:1f.2": "/sys/bus/pci/devices/0000?00?1f.2",
		"/data/{a,b}/*?@~=[x]":              "/data/?a?b?/??????x?",
		"/tmp/caf\u00e9":                    "/tmp/caf??",
		"/tmp/removed (deleted)":            "/tmp/removed (deleted)",
		"/tmp/removed:1 (deleted)":          "/tmp/removed?1 (deleted)",
		"/anon_hugepage (deleted)":          "/anon_hugepage (deleted)",
		"/tmp/(not deleted)":                "/tmp/?not deleted?",
	} {
		require.Equal(t, want, sanitizeFilePath(path), "path %q", path)
	}
}

// TestHandleFileEventProducesValidPaths asserts that recorded paths make it
// into the profile validation instead of failing it.
func TestHandleFileEventProducesValidPaths(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()
	sut.handleFileEvent(fileEvent(testKey, flagRead, "/sys/bus/pci/devices/0000:00:1f.2/config"))

	require.Contains(t,
		sut.recordedFiles[recordingKey(testKey)], "/sys/bus/pci/devices/0000?00?1f.2/config")
}

// profilePathPattern is the pattern the AppArmorProfile API and crd2armor
// accept for paths.
var profilePathPattern = regexp.MustCompile(
	`^(?:/[a-zA-Z0-9_./*?+@{} -]*|ptrace\s*\([a-zA-Z]+\),(?:\s*#.*)?)$`,
)

// TestRecordedPathsAreAccepted asserts that no recorded path gets the whole
// recorded profile rejected, whatever the kernel reports.
func TestRecordedPathsAreAccepted(t *testing.T) {
	t.Parallel()

	sut := newTestAppArmorRecorder()

	paths := []string{
		"",
		"relative/path",
		"/proc/1234/task/5678/stat",
		"/sys/devices/pci0000:00/0000:00:1f.2/config",
		"/sys/bus/pci/devices/0000:00:1f.2/config",
		"/var/lib/containers/storage/overlay/abc123/diff",
		"/run/secrets/kubernetes.io/serviceaccount/..2024_01_01_00_00_00.123456789/token",
		"/tmp/removed:1 (deleted)",
		"/anon_hugepage (deleted)",
		"/tmp/caf\u00e9/\u6587\u4ef6",
	}

	// Every byte a path can contain, in a spot where no variance is replaced.
	for c := 1; c < 256; c++ {
		paths = append(paths, "/dir"+string([]byte{byte(c)})+"x/file")
	}

	for _, path := range paths {
		// Separate directories keep the accesses from merging into one rule.
		if !strings.HasPrefix(path, "/") {
			sut.handleFileEvent(fileEvent(testKey, flagRead, path))

			continue
		}

		sut.handleFileEvent(fileEvent(testKey, flagRead, "/ro"+path))
		sut.handleFileEvent(fileEvent(testKey+1, flagSpawn, "/exe"+path))
		sut.handleFileEvent(fileEvent(testKey+2, flagExec, "/lib"+path))
		sut.handleFileEvent(fileEvent(testKey+3, flagWrite, "/wo"+path))
		sut.handleFileEvent(fileEvent(testKey+4, flagRead|flagWrite, "/rw"+path))
	}

	got, ok := sut.GetAppArmorProcessed(
		[]uint64{testKey, testKey + 1, testKey + 2, testKey + 3, testKey + 4},
	)
	require.True(t, ok)

	for name, list := range map[string][]string{
		"executables":      got.FileProcessed.AllowedExecutables,
		"libraries":        got.FileProcessed.AllowedLibraries,
		"read only paths":  got.FileProcessed.ReadOnlyPaths,
		"write only paths": got.FileProcessed.WriteOnlyPaths,
		"read write paths": got.FileProcessed.ReadWritePaths,
	} {
		require.NotEmpty(t, list, name)

		for _, path := range list {
			require.Regexp(t, profilePathPattern, path, name)
		}
	}

	_, err := crd2armor.GenerateProfile(
		"test",
		"",
		new(crd2armor.AbstractFromRecording(&crd2armor.RecordedAccess{
			AllowedExecutables: got.FileProcessed.AllowedExecutables,
			AllowedLibraries:   got.FileProcessed.AllowedLibraries,
			ReadOnlyPaths:      got.FileProcessed.ReadOnlyPaths,
			WriteOnlyPaths:     got.FileProcessed.WriteOnlyPaths,
			ReadWritePaths:     got.FileProcessed.ReadWritePaths,
		})),
	)
	require.NoError(t, err)
}

// TestProcessedFileRules covers how the accesses of the keys of a container
// become profile rules.
func TestProcessedFileRules(t *testing.T) {
	t.Parallel()

	t.Run("write and execute from different keys keep both", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagWrite, "/app/plugin.so"))
		sut.handleFileEvent(fileEvent(2, flagExec, "/app/plugin.so"))
		sut.handleFileEvent(fileEvent(1, flagWrite, "/app/tool"))
		sut.handleFileEvent(fileEvent(2, flagSpawn, "/app/tool"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1, 2})
		require.True(t, ok)

		require.Equal(t, []string{"/app/plugin.so"}, got.FileProcessed.AllowedLibraries)
		require.Equal(t, []string{"/app/tool"}, got.FileProcessed.AllowedExecutables)
		// A write only rule would deny the reading executing needs.
		require.Empty(t, got.FileProcessed.WriteOnlyPaths)
		require.Equal(t, []string{"/app/*"}, got.FileProcessed.ReadWritePaths)
	})

	t.Run("execute wins within a key", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagWrite|flagSpawn, "/app/tool"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1})
		require.True(t, ok)

		require.Equal(t, []string{"/app/tool"}, got.FileProcessed.AllowedExecutables)
		require.Empty(t, got.FileProcessed.ReadWritePaths)
		require.Empty(t, got.FileProcessed.WriteOnlyPaths)
	})

	t.Run("reads and writes from different keys become read write", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagRead, "/data/file"))
		sut.handleFileEvent(fileEvent(2, flagWrite, "/data/file"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1, 2})
		require.True(t, ok)

		require.Equal(t, []string{"/data/file"}, got.FileProcessed.ReadWritePaths)
		require.Empty(t, got.FileProcessed.ReadOnlyPaths)
		require.Empty(t, got.FileProcessed.WriteOnlyPaths)
	})

	t.Run("deleted directories are skipped", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagRead|flagWrite, "/tmp/gone (deleted)/"))
		sut.handleFileEvent(fileEvent(1, flagRead|flagWrite, "/tmp/gone:1 (deleted)"))
		sut.handleFileEvent(fileEvent(1, flagRead, "/etc/passwd"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1})
		require.True(t, ok)

		require.Equal(t, []string{"/etc/passwd"}, got.FileProcessed.ReadOnlyPaths)
		require.Empty(t, got.FileProcessed.ReadWritePaths)
	})

	t.Run("huge page workaround is added once", func(t *testing.T) {
		t.Parallel()

		sut := newTestAppArmorRecorder()
		sut.handleFileEvent(fileEvent(1, flagRead, "/anon_hugepage (deleted)"))
		sut.handleFileEvent(fileEvent(2, flagRead, "/anon_hugepage (deleted)"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1, 2})
		require.True(t, ok)

		require.Equal(t, []string{"/"}, got.FileProcessed.ReadWritePaths)
	})

	t.Run("the recorded program is compared sanitized", func(t *testing.T) {
		t.Parallel()

		sut := newAppArmorRecorder(logr.Discard(), "/opt/app:v1/bin")
		sut.handleFileEvent(fileEvent(1, flagExec, "/opt/app:v1/bin"))

		got, ok := sut.GetAppArmorProcessed([]uint64{1})
		require.True(t, ok)

		require.Empty(t, got.FileProcessed.AllowedLibraries)
	})
}
