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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := replaceVarianceInFilePath(tc.path)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAllowAnyFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{
			name:  "allow any files if at least two files are already allowed",
			paths: []string{"/etc/nginx/conf.d/default.conf", "/dev/null", "/etc/nginx/conf.d/sedIWASqqq"},
			want:  []string{"/etc/nginx/conf.d/*", "/dev/null"},
		},
		{
			name: "allow any files if more than two files are already allowed",
			paths: []string{
				"/etc/nginx/conf.d/default.conf", "/dev/null",
				"/etc/nginx/conf.d/sedIWASqqq", "/etc/nginx/conf.d/abcd",
			},
			want: []string{"/etc/nginx/conf.d/*", "/dev/null"},
		},
		{
			name:  "do not allow any files ",
			paths: []string{"/etc/nginx/conf.d/default.conf", "/dev/null"},
			want:  []string{"/etc/nginx/conf.d/default.conf", "/dev/null"},
		},
		{
			name:  "do not allow anything if nothing is allowed",
			paths: []string{},
			want:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := allowAnyFiles(test.paths)
			require.Equal(t, test.want, got)
		})
	}
}

func TestShouldExcludeFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "Should exclude containerd file",
			filePath: "/run/containerd/io.containerd.runtime.v2.task/k8s.io/1806f41e981228490db/rootfs",
			want:     true,
		},
		{
			name:     "Should exclude runc binary",
			filePath: "/usr/bin/runc",
			want:     true,
		},
		{
			name:     "Should not exclude normal files",
			filePath: "/etc/group",
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := shouldExcludeFile(test.filePath)
			require.Equal(t, test.want, got)
		})
	}
}
