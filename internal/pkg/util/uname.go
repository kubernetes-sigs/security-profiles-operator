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

package util

import (
	"fmt"
	"regexp"

	"github.com/blang/semver/v4"
	"golang.org/x/sys/unix"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
)

// releaseRegexp matches the numeric part of a kernel release. Distribution
// suffixes like `-427.13.1.el9_4.x86_64`, `-45-generic` or `+` are not valid
// semver, so they get ignored.
var releaseRegexp = regexp.MustCompile(`^\d+\.\d+(\.\d+)?`)

// parseRelease returns the major, minor and patch version of a kernel
// release.
func parseRelease(release string) (semver.Version, error) {
	version, err := semver.ParseTolerant(releaseRegexp.FindString(release))
	if err != nil {
		return semver.Version{}, fmt.Errorf("unable to parse kernel release %q: %w", release, err)
	}

	return version, nil
}

func Uname() (types.Arch, *semver.Version, error) {
	// The fields are byte arrays on every architecture, unlike the ones of
	// the syscall package.
	uname := unix.Utsname{}
	if err := unix.Uname(&uname); err != nil {
		return "", nil, fmt.Errorf("uname syscall failed: %w", err)
	}

	arch := types.Arch(unix.ByteSliceToString(uname.Machine[:]))

	version, err := parseRelease(unix.ByteSliceToString(uname.Release[:]))
	if err != nil {
		return "", nil, err
	}

	return arch, &version, nil
}
