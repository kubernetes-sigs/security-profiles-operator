/*
Copyright 2026 The Kubernetes Authors.

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

package util

import (
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func TestSyscallsRoundTrip(t *testing.T) {
	t.Parallel()

	input := []seccompprofile.Syscall{
		{
			Names:    []string{"read", "write"},
			Action:   seccompprofile.ActAllow,
			ErrnoRet: 0,
			Args: []seccompprofile.Arg{
				{Index: ptr.To[int32](0), Value: 42, ValueTwo: 100, Op: "SCMP_CMP_EQ"},
			},
		},
		{
			Names:    []string{"open"},
			Action:   seccompprofile.ActErrno,
			ErrnoRet: 13,
		},
		{
			Names:  []string{"close"},
			Action: seccompprofile.ActLog,
		},
	}

	oci := syscallsToOCI(input)
	require.Len(t, oci, 3)
	require.Equal(t, specs.LinuxSeccompAction("SCMP_ACT_ALLOW"), oci[0].Action)
	require.Equal(t, uint(13), *oci[1].ErrnoRet)
	require.Nil(t, oci[2].ErrnoRet)

	roundTripped := syscallsFromOCI(oci)
	require.Equal(t, input, roundTripped)
}

func TestArgsRoundTrip(t *testing.T) {
	t.Parallel()

	input := []seccompprofile.Arg{
		{Index: ptr.To[int32](0), Value: 1, ValueTwo: 2, Op: "SCMP_CMP_EQ"},
		{Index: ptr.To[int32](3), Value: 100, ValueTwo: 0, Op: "SCMP_CMP_GE"},
	}

	oci := argsToOCI(input)
	require.Len(t, oci, 2)
	require.Equal(t, uint(0), oci[0].Index)
	require.Equal(t, uint64(1), oci[0].Value)
	require.Equal(t, specs.OpEqualTo, oci[0].Op)

	roundTripped := argsFromOCI(oci)
	require.Equal(t, input, roundTripped)
}

func TestArgsEmptyNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, argsToOCI(nil))
	require.Nil(t, argsToOCI([]seccompprofile.Arg{}))
	require.Nil(t, argsFromOCI(nil))
	require.Nil(t, argsFromOCI([]specs.LinuxSeccompArg{}))
}

func TestArgsNilIndex(t *testing.T) {
	t.Parallel()

	input := []seccompprofile.Arg{
		{Index: nil, Value: 5},
	}

	oci := argsToOCI(input)
	require.Equal(t, uint(0), oci[0].Index)

	roundTripped := argsFromOCI(oci)
	require.Equal(t, int32(0), *roundTripped[0].Index)
}

func TestErrnoRetRoundTrip(t *testing.T) {
	t.Parallel()

	require.Nil(t, errnoRetToOCI(0))
	require.Equal(t, int32(0), errnoRetFromOCI(nil))

	val := errnoRetToOCI(13)
	require.Equal(t, uint(13), *val)
	require.Equal(t, int32(13), errnoRetFromOCI(val))
}
