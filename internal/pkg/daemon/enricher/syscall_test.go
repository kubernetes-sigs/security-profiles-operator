//go:build linux

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
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func TestSyscallName(t *testing.T) {
	t.Parallel()

	// The syscall numbers differ between the architectures.
	name, err := syscallName(102, "40000003")
	require.NoError(t, err)
	require.Equal(t, "socketcall", name)

	name, err = syscallName(102, "c000003e")
	require.NoError(t, err)
	require.Equal(t, "getuid", name)

	// s390 is printed without leading zeros.
	name, err = syscallName(102, "16")
	require.NoError(t, err)
	require.Equal(t, "socketcall", name)

	name, err = syscallName(0, "")
	require.NoError(t, err)
	require.NotEmpty(t, name)
}

func TestIsNativeArch(t *testing.T) {
	t.Parallel()

	require.True(t, isNativeArch(""))
	require.True(t, isNativeArch(nativeAuditArches[runtime.GOARCH]))
	require.False(t, isNativeArch("ffffffff"))
}

// TestDispatchSeccompLineSkipsCompatSyscalls asserts that a syscall of a compat
// architecture does not end up in a recorded profile, which only covers the
// native one, under the name of an unrelated native syscall.
func TestDispatchSeccompLineSkipsCompatSyscalls(t *testing.T) {
	t.Parallel()

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	info := &types.ContainerInfo{SeccompRecordProfile: "profile"}

	sut.dispatchSeccompLine(node, &types.AuditLine{
		AuditType: types.AuditTypeSeccomp, SystemCallID: 102, Arch: "40000003",
	}, info)
	_, found := sut.syscalls.get("profile", "", false)
	require.False(t, found)

	sut.dispatchSeccompLine(node, &types.AuditLine{
		AuditType: types.AuditTypeSeccomp, SystemCallID: 0, Arch: nativeAuditArches[runtime.GOARCH],
	}, info)

	recorded, found := sut.syscalls.get("profile", "", false)
	require.True(t, found)
	require.Len(t, recorded, 1)
}

// TestJsonDispatchResolvesArchPerLine asserts that the syscalls of a process
// are named with the architecture of each audit line, as a process can use
// the ones of several architectures.
func TestJsonDispatchResolvesArchPerLine(t *testing.T) {
	t.Parallel()

	mock := &enricherfakes.FakeImpl{}

	sut, err := NewJsonEnricherArgs(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock

	bucket := &types.LogBucket{
		TimestampID: "1613173578.156:2945",
		ProcessInfo: &types.ProcessInfo{Pid: 1},
		SyscallIds: map[types.SyscallKey]struct{}{
			{ID: 102, Arch: "c000003e"}: {},
			{ID: 102, Arch: "40000003"}: {},
		},
	}

	sut.dispatchSeccompLine(bucket, "node")

	require.Equal(t, 1, mock.PrintJsonOutputCallCount())

	_, output := mock.PrintJsonOutputArgsForCall(0)

	audit := struct {
		Syscalls []string `json:"syscalls"`
	}{}
	require.NoError(t, json.Unmarshal(output, &audit))
	require.ElementsMatch(t, []string{"getuid", "socketcall"}, audit.Syscalls)
}

// The syscall IDs of the audit lines are arbitrary numbers, the warnings
// about unknown ones must not remember each of them.
func TestUnknownSyscallWarnedOncePerArch(t *testing.T) {
	t.Parallel()

	var logged []string

	logger := funcr.New(func(_, args string) {
		logged = append(logged, args)
	}, funcr.Options{})

	warner := &onceWarner{}
	for id := range 100 {
		warner.warn(logger, unknownSyscallKey("c000003e"), "no syscall name found for ID", "id", id)
	}

	warner.warn(logger, unknownSyscallKey("40000028"), "no syscall name found for ID", "id", 1)

	// The architecture of the audit lines is arbitrary as well.
	for arch := range 100 {
		warner.warn(logger, unknownSyscallKey(fmt.Sprintf("bogus%d", arch)),
			"no syscall name found for ID", "id", 1)
	}

	require.Len(t, logged, 3)

	keys := 0

	warner.keys.Range(func(any, any) bool {
		keys++

		return true
	})
	require.Equal(t, 3, keys)
}

// TestSyscallNameCached asserts that the names of the syscalls are cached per
// architecture, and that unknown ones are not.
func TestSyscallNameCached(t *testing.T) {
	t.Parallel()

	for range 2 {
		name, err := syscallName(0, "c000003e")
		require.NoError(t, err)
		require.Equal(t, "read", name)

		name, err = syscallName(0, "c00000b7")
		require.NoError(t, err)
		require.Equal(t, "io_setup", name)
	}

	_, cached := syscallNames.Load(syscallKey{id: 0, arch: "c000003e"})
	require.True(t, cached)

	_, err := syscallName(-1000, "c000003e")
	require.Error(t, err)

	_, cached = syscallNames.Load(syscallKey{id: -1000, arch: "c000003e"})
	require.False(t, cached)
}
