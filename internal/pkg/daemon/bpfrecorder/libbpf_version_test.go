//go:build linux && !no_bpf

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

package bpfrecorder

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/stretchr/testify/require"
)

// libbpfgoTagRegex matches the libbpf version libbpfgo encodes into its module
// version, like v0.11.0-libbpf-1.7 or v0.11.0-libbpf-1.8-dev-2bbc483.
var libbpfgoTagRegex = regexp.MustCompile(
	`(?m)^(?:require)?\s*github\.com/aquasecurity/libbpfgo\s+v\S*-libbpf-(\d+)\.(\d+)(-dev)?\S*\s*$`,
)

// libbpfgoTagVersion returns the libbpf version of the libbpfgo module
// version in go.mod, and whether it is a snapshot of the libbpf development
// branch.
func libbpfgoTagVersion(t *testing.T, goMod []byte) (major, minor int, dev bool) {
	t.Helper()

	match := libbpfgoTagRegex.FindSubmatch(goMod)
	require.NotNil(t, match, "no libbpf version in the libbpfgo module version of go.mod")

	major, err := strconv.Atoi(string(match[1]))
	require.NoError(t, err)

	minor, err = strconv.Atoi(string(match[2]))
	require.NoError(t, err)

	return major, minor, len(match[3]) > 0
}

// TestLinkedLibbpfMatchesLibbpfgo asserts that the libbpf the binaries are
// linked with is the one libbpfgo was written for. libbpfgo binds to the C
// API of a particular libbpf version, and the libbpf of hack/install-libbpf.sh
// and of nix is bumped independently of the Go module.
//
// A development snapshot of libbpfgo, tagged -libbpf-X.Y-dev, follows the
// development branch of libbpf, which carries the version of its next release
// X.Y. It still works with the last release X.Y-1, which is what the
// distributions ship until X.Y is out, so both are accepted for it.
func TestLinkedLibbpfMatchesLibbpfgo(t *testing.T) {
	t.Parallel()

	goMod, err := os.ReadFile("../../../../go.mod")
	require.NoError(t, err)

	major, minor, dev := libbpfgoTagVersion(t, goMod)
	linkedMajor, linkedMinor := bpf.MajorVersion(), bpf.MinorVersion()

	if dev && linkedMajor == major && linkedMinor == minor-1 {
		return
	}

	require.Equal(t, [2]int{major, minor}, [2]int{linkedMajor, linkedMinor},
		"libbpf %s is linked, but libbpfgo in go.mod is for libbpf %d.%d, "+
			"bump hack/install-libbpf.sh, nix or go.mod together",
		bpf.LibbpfVersionString(), major, minor)
}

func TestLibbpfgoTagVersion(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		line         string
		major, minor int
		dev          bool
	}{
		{line: "\tgithub.com/aquasecurity/libbpfgo v0.11.0-libbpf-1.7\n", major: 1, minor: 7},
		{
			line:  "\tgithub.com/aquasecurity/libbpfgo v0.11.0-libbpf-1.8-dev-2bbc483\n",
			major: 1, minor: 8, dev: true,
		},
		{line: "require github.com/aquasecurity/libbpfgo v0.9.2-libbpf-1.5.1\n", major: 1, minor: 5},
	} {
		t.Run(tc.line, func(t *testing.T) {
			t.Parallel()

			major, minor, dev := libbpfgoTagVersion(t, []byte(tc.line))
			require.Equal(t, tc.major, major)
			require.Equal(t, tc.minor, minor)
			require.Equal(t, tc.dev, dev)
		})
	}
}
