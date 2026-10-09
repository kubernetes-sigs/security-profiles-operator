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

	oci, err := syscallsToOCI(input)
	require.NoError(t, err)
	require.Len(t, oci, 3)
	require.Equal(t, specs.LinuxSeccompAction("SCMP_ACT_ALLOW"), oci[0].Action)
	require.Equal(t, uint(13), *oci[1].ErrnoRet)
	require.Nil(t, oci[2].ErrnoRet)

	roundTripped, err := syscallsFromOCI(oci)
	require.NoError(t, err)
	require.Equal(t, input, roundTripped)
}

// Base profiles from a registry or a file skip the CRD validation, so values
// which would wrap around in the runtime-spec must be rejected.
func TestSyscallsToOCIOutOfRange(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		arg  seccompprofile.Arg
		want string
	}{
		{
			name: "NegativeValue",
			arg:  seccompprofile.Arg{Index: ptr.To[int32](0), Value: -1, Op: "SCMP_CMP_EQ"},
			want: "syscalls [personality]: seccomp value out of range: negative value -1",
		},
		{
			name: "NegativeValueTwo",
			arg:  seccompprofile.Arg{Index: ptr.To[int32](0), Value: 1, ValueTwo: math.MinInt64, Op: "SCMP_CMP_MASKED_EQ"},
			want: "syscalls [personality]: seccomp value out of range: negative valueTwo -9223372036854775808",
		},
		{
			name: "NegativeIndex",
			arg:  seccompprofile.Arg{Index: ptr.To[int32](-1), Op: "SCMP_CMP_EQ"},
			want: "syscalls [personality]: seccomp value out of range: index -1 is not between 0 and 5",
		},
		{
			name: "IndexTooLarge",
			arg:  seccompprofile.Arg{Index: ptr.To[int32](6), Op: "SCMP_CMP_EQ"},
			want: "syscalls [personality]: seccomp value out of range: index 6 is not between 0 and 5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := syscallsToOCI([]seccompprofile.Syscall{{
				Names:  []string{"personality"},
				Action: seccompprofile.ActAllow,
				Args:   []seccompprofile.Arg{tc.arg},
			}})
			require.ErrorIs(t, err, ErrSeccompArgOutOfRange)
			require.EqualError(t, err, tc.want)
		})
	}
}

func TestArgsToOCIBounds(t *testing.T) {
	t.Parallel()

	oci, err := argsToOCI([]seccompprofile.Arg{
		{
			Index:    ptr.To[int32](5),
			Value:    math.MaxInt64,
			ValueTwo: math.MaxInt64,
			Op:       "SCMP_CMP_MASKED_EQ",
		},
	})
	require.NoError(t, err)
	require.Equal(t, uint(5), oci[0].Index)
	require.Equal(t, uint64(math.MaxInt64), oci[0].Value)
	require.Equal(t, uint64(math.MaxInt64), oci[0].ValueTwo)
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

	oci, err := argsToOCI(input)
	require.NoError(t, err)
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

	oci, err := argsToOCI(nil)
	require.NoError(t, err)
	require.Nil(t, oci)

	oci, err = argsToOCI([]seccompprofile.Arg{})
	require.NoError(t, err)
	require.Nil(t, oci)

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

	oci, err := argsToOCI(input)
	require.NoError(t, err)
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
