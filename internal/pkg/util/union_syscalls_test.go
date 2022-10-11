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
	"sort"
	"testing"

	"github.com/containers/common/pkg/seccomp"
	"github.com/stretchr/testify/require"

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
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1beta1.Syscall{
				{
					Names:  []string{"d", "e", "f"},
					Action: seccomp.Action("foo"),
				},
			},
			want: []*v1beta1.Syscall{
				{
					Names:  []string{"a", "b", "c", "d", "e", "f"},
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
					Names:  []string{"a", "b", "c", "d"},
					Action: seccomp.Action("foo"),
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := UnionSyscalls(tc.baseSyscalls, tc.appliedSyscalls)
			for i := range got {
				sort.Strings(got[i].Names)
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].Action < got[j].Action
			})
			require.Equal(t, tc.want, got)
		})
	}
}
