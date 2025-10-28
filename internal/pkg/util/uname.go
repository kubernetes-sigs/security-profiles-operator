//go:build linux

/*
Copyright 2025 The Kubernetes Authors.

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
	"strings"
	"syscall"

	"github.com/blang/semver/v4"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
)

func normalizeRelease(release string) string {
	// Work around kernels with empty build metadata, e.g. `6.6.93+`.
	return strings.TrimSuffix(release, "+")
}

func Uname() (types.Arch, *semver.Version, error) {
	uname := syscall.Utsname{}
	if err := syscall.Uname(&uname); err != nil {
		return "", nil, fmt.Errorf("uname syscall failed: %w", err)
	}

	arch := types.Arch(unameMachineToString(&uname))
	release := unameReleaseToString(&uname)
	release = normalizeRelease(release)

	version, err := semver.Parse(release)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse semver for release %s: %w", release, err)
	}

	version.Pre = nil

	return arch, &version, nil
}
