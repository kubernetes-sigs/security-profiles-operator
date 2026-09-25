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
	"runtime"
	"testing"

	"github.com/go-logr/logr"
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

	info := &types.ContainerInfo{RecordProfile: "profile"}

	sut.dispatchSeccompLine(node, &types.AuditLine{
		AuditType: types.AuditTypeSeccomp, SystemCallID: 102, Arch: "40000003",
	}, info)
	require.Nil(t, sut.syscalls.Get("profile"))

	sut.dispatchSeccompLine(node, &types.AuditLine{
		AuditType: types.AuditTypeSeccomp, SystemCallID: 0, Arch: nativeAuditArches[runtime.GOARCH],
	}, info)

	item := sut.syscalls.Get("profile")
	require.NotNil(t, item)
	require.Len(t, item.Value().UnsortedList(), 1)
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
	}
	bucket.SyscallIds.Store(types.SyscallKey{ID: 102, Arch: "c000003e"}, struct{}{})
	bucket.SyscallIds.Store(types.SyscallKey{ID: 102, Arch: "40000003"}, struct{}{})

	sut.dispatchSeccompLine(bucket, "node")

	require.Equal(t, 1, mock.PrintJsonOutputCallCount())

	_, output := mock.PrintJsonOutputArgsForCall(0)

	audit := struct {
		Syscalls []string `json:"syscalls"`
	}{}
	require.NoError(t, json.Unmarshal(output, &audit))
	require.ElementsMatch(t, []string{"getuid", "socketcall"}, audit.Syscalls)
}
