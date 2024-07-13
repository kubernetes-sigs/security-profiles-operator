//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2024 The Kubernetes Authors.

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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplaceVarianceInFilePath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want string
	}{
		{
			name: "no replacement",
			path: "/sys/module/apparmor/parameters/enabled",
			want: "/sys/module/apparmor/parameters/enabled",
		},
		{
			name: "replace only PID",
			path: "/proc/123/cgroup",
			want: "/proc/@{pid}/cgroup",
		},
		{
			name: "replace PID and TID",
			path: "/proc/123/task/12948/attr/apparmor",
			want: "/proc/@{pid}/task/@{tid}/attr/apparmor",
		},
		{
			name: "replace container ID",
			path: "/var/lib/containers/storage/overlay/8a0a50ee00/merged/dev",
			want: "/var/lib/containers/storage/overlay/*/merged/dev",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := replaceVarianceInFilePath(tc.path)
			require.Equal(t, tc.want, got)
		})
	}
}
