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
	"go.podman.io/common/pkg/seccomp"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

func TestUnionSyscalls(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		baseSyscalls    []*v1beta1.Syscall
		appliedSyscalls []*v1beta1.Syscall
		want            []*v1beta1.Syscall
	}{
		{
			name:            "BothEmpty",
			baseSyscalls:    []*v1beta1.Syscall{},
			appliedSyscalls: []*v1beta1.Syscall{},
			want:            []*v1beta1.Syscall{},
		},
		{
			name:         "BaseEmpty",
			baseSyscalls: []*v1beta1.Syscall{},
			appliedSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "AppliedEmpty",
			baseSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1beta1.Syscall{},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "Args",
			baseSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
					Args:   []*v1beta1.Arg{{Index: 1, Value: 2}},
				},
			},
			appliedSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
					Args:   []*v1beta1.Arg{{Index: 2, Value: 3}},
				},
			},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
					Args:   []*v1beta1.Arg{{Index: 1, Value: 2}},
				},
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
					Args:   []*v1beta1.Arg{{Index: 2, Value: 3}},
				},
			},
		},
		{
			name: "UniqueActions",
			baseSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("bar"),
				},
			},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("bar"),
				},
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "OverlappingActionsWithUniqueNames",
			baseSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "c", "b"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"d", "f", "e"},
					Action: seccomp.Action("foo"),
				},
			},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
				{
					Names:  []string{"d", "e", "f"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "OverlappingActionsWithOverlappingNames",
			baseSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
			},
			appliedSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"b", "c", "d"},
					Action: seccomp.Action("foo"),
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
			},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
				{
					Names:  []string{"b", "c", "d"},
					Action: seccomp.Action("foo"),
				},
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
