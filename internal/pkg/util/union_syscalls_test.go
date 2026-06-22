/*
Copyright 2020 The Kubernetes Authors.

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

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func TestUnionSyscalls(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		baseSyscalls    []seccompprofileapi.Syscall
		appliedSyscalls []seccompprofileapi.Syscall
		want            []seccompprofileapi.Syscall
	}{
		{
			name:            "BothEmpty",
			baseSyscalls:    []seccompprofileapi.Syscall{},
			appliedSyscalls: []seccompprofileapi.Syscall{},
			want:            []seccompprofileapi.Syscall{},
		},
		{
			name:         "BaseEmpty",
			baseSyscalls: []seccompprofileapi.Syscall{},
			appliedSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActAllow,
				},
			},
			want: []seccompprofileapi.Syscall{
				{Names: []string{"a"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"b"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"c"}, Action: seccompprofileapi.ActAllow},
			},
		},
		{
			name: "AppliedEmpty",
			baseSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActAllow,
				},
			},
			appliedSyscalls: []seccompprofileapi.Syscall{},
			want: []seccompprofileapi.Syscall{
				{Names: []string{"a"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"b"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"c"}, Action: seccompprofileapi.ActAllow},
			},
		},
		{
			name: "Args",
			baseSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActAllow,
					Args:   []seccompprofileapi.Arg{{Index: ptr.To[int32](1), Value: 2}},
				},
			},
			appliedSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActAllow,
					Args:   []seccompprofileapi.Arg{{Index: ptr.To[int32](2), Value: 3}},
				},
			},
			want: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a"},
					Action: seccompprofileapi.ActAllow,
					Args: []seccompprofileapi.Arg{
						{Index: ptr.To[int32](1), Value: 2},
						{Index: ptr.To[int32](2), Value: 3},
					},
				},
				{
					Names:  []string{"b"},
					Action: seccompprofileapi.ActAllow,
					Args: []seccompprofileapi.Arg{
						{Index: ptr.To[int32](1), Value: 2},
						{Index: ptr.To[int32](2), Value: 3},
					},
				},
				{
					Names:  []string{"c"},
					Action: seccompprofileapi.ActAllow,
					Args: []seccompprofileapi.Arg{
						{Index: ptr.To[int32](1), Value: 2},
						{Index: ptr.To[int32](2), Value: 3},
					},
				},
			},
		},
		{
			name: "DifferentActionsPicksLessRestrictive",
			baseSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActAllow,
				},
			},
			appliedSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActLog,
				},
			},
			want: []seccompprofileapi.Syscall{
				{Names: []string{"a"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"b"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"c"}, Action: seccompprofileapi.ActAllow},
			},
		},
		{
			name: "SameActionUniqueNames",
			baseSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "c", "b"},
					Action: seccompprofileapi.ActAllow,
				},
			},
			appliedSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"d", "f", "e"},
					Action: seccompprofileapi.ActAllow,
				},
			},
			want: []seccompprofileapi.Syscall{
				{Names: []string{"a"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"b"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"c"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"d"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"e"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"f"}, Action: seccompprofileapi.ActAllow},
			},
		},
		{
			name: "OverlappingNamesDeduplicatedAndNormalized",
			baseSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccompprofileapi.ActAllow,
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccompprofileapi.ActLog,
				},
			},
			appliedSyscalls: []seccompprofileapi.Syscall{
				{
					Names:  []string{"b", "c", "d"},
					Action: seccompprofileapi.ActAllow,
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccompprofileapi.ActLog,
				},
			},
			want: []seccompprofileapi.Syscall{
				{Names: []string{"a"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"b"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"c"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"d"}, Action: seccompprofileapi.ActAllow},
				{Names: []string{"x"}, Action: seccompprofileapi.ActLog},
				{Names: []string{"y"}, Action: seccompprofileapi.ActLog},
				{Names: []string{"z"}, Action: seccompprofileapi.ActLog},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := UnionSyscalls(tc.baseSyscalls, tc.appliedSyscalls)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
