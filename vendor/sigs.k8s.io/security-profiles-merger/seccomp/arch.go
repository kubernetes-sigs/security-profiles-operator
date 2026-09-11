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

package seccomp

import (
	"errors"
	"fmt"
	"runtime"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ErrUnknownNativeArchitecture is returned by PopulateNativeArchitecture
// when the architecture of the running program has no seccomp
// architecture constant.
var ErrUnknownNativeArchitecture = errors.New(
	"no seccomp architecture for the native architecture",
)

// NativeArchitecture returns the seccomp architecture of the running
// program, derived from runtime.GOARCH. The second result is false when
// GOARCH has no seccomp architecture constant.
func NativeArchitecture() (specs.Arch, bool) {
	arch, ok := nativeArchitectures[runtime.GOARCH]

	return arch, ok
}

// PopulateNativeArchitecture sets the profile's Architectures to the native
// architecture when the list is empty, which is what an empty list means
// per the OCI runtime-spec. Intersect treats an empty list as unspecified
// instead, so runtimes call this on every input before merging to get a
// precise architecture intersection. A profile that already lists
// architectures is left unchanged. It returns ErrNilProfile for a nil
// profile and ErrUnknownNativeArchitecture when the native architecture is
// unknown.
func PopulateNativeArchitecture(profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	if len(profile.Architectures) > 0 {
		return nil
	}

	arch, ok := NativeArchitecture()
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownNativeArchitecture, runtime.GOARCH)
	}

	profile.Architectures = []specs.Arch{arch}

	return nil
}

// nativeArchitectures maps runtime.GOARCH values to seccomp architectures.
//
//nolint:gochecknoglobals // immutable lookup table
var nativeArchitectures = map[string]specs.Arch{
	"386":      specs.ArchX86,
	"amd64":    specs.ArchX86_64,
	"arm":      specs.ArchARM,
	"arm64":    specs.ArchAARCH64,
	"loong64":  specs.ArchLOONGARCH64,
	"mips":     specs.ArchMIPS,
	"mips64":   specs.ArchMIPS64,
	"mips64le": specs.ArchMIPSEL64,
	"mipsle":   specs.ArchMIPSEL,
	"ppc64":    specs.ArchPPC64,
	"ppc64le":  specs.ArchPPC64LE,
	"riscv64":  specs.ArchRISCV64,
	"s390x":    specs.ArchS390X,
}
