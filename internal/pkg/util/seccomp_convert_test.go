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

package util

import (
	"math"
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

	roundTripped, err := syscallsFromOCI(oci)
	require.NoError(t, err)
	require.Equal(t, input, roundTripped)
}

func TestSyscallsFromOCIOutOfRange(t *testing.T) {
	t.Parallel()

	_, err := syscallsFromOCI([]specs.LinuxSyscall{{
		Names:  []string{"personality"},
		Action: specs.ActAllow,
		Args: []specs.LinuxSeccompArg{
			{Index: 0, Value: math.MaxUint64, Op: specs.OpEqualTo},
		},
	}})
	require.ErrorIs(t, err, ErrSeccompArgOutOfRange)
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

	roundTripped, err := argsFromOCI(oci)
	require.NoError(t, err)
	require.Equal(t, input, roundTripped)
}

func TestArgsEmptyNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, argsToOCI(nil))
	require.Nil(t, argsToOCI([]seccompprofile.Arg{}))

	args, err := argsFromOCI(nil)
	require.NoError(t, err)
	require.Nil(t, args)

	args, err = argsFromOCI([]specs.LinuxSeccompArg{})
	require.NoError(t, err)
	require.Nil(t, args)
}

func TestArgsNilIndex(t *testing.T) {
	t.Parallel()

	input := []seccompprofile.Arg{
		{Index: nil, Value: 5},
	}

	oci := argsToOCI(input)
	require.Equal(t, uint(0), oci[0].Index)

	roundTripped, err := argsFromOCI(oci)
	require.NoError(t, err)
	require.Equal(t, int32(0), *roundTripped[0].Index)
}

func TestArgsFromOCIOutOfRange(t *testing.T) {
	t.Parallel()

	for _, arg := range []specs.LinuxSeccompArg{
		{Index: math.MaxInt32 + 1},
		{Value: math.MaxInt64 + 1},
		{ValueTwo: math.MaxUint64},
	} {
		_, err := argsFromOCI([]specs.LinuxSeccompArg{arg})
		require.ErrorIs(t, err, ErrSeccompArgOutOfRange)
	}
}

func TestErrnoRetRoundTrip(t *testing.T) {
	t.Parallel()

	require.Nil(t, errnoRetToOCI(0))

	ret, err := errnoRetFromOCI(nil)
	require.NoError(t, err)
	require.Equal(t, int32(0), ret)

	val := errnoRetToOCI(13)
	require.Equal(t, uint(13), *val)

	ret, err = errnoRetFromOCI(val)
	require.NoError(t, err)
	require.Equal(t, int32(13), ret)
}

func TestErrnoRetNegativeSkipped(t *testing.T) {
	t.Parallel()

	require.Nil(t, errnoRetToOCI(-1))
}

func TestErrnoRetFromOCIOverflow(t *testing.T) {
	t.Parallel()

	overflow := uint(1 << 31)
	_, err := errnoRetFromOCI(&overflow)
	require.ErrorIs(t, err, ErrSeccompArgOutOfRange)
}
