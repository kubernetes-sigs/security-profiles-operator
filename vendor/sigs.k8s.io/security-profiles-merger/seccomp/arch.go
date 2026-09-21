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
	"runtime"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// NativeArchitecture returns the seccomp architecture of the running
// program, derived from runtime.GOARCH. The second result is false when
// GOARCH has no seccomp architecture constant.
//
// Runtimes always include the native architecture in a filter, whether or
// not the profile lists it, so Intersect and Union need no help to account
// for it. This is for callers that want to spell it out, for example when
// reporting which architectures a merged profile covers.
func NativeArchitecture() (specs.Arch, bool) {
	arch, ok := nativeArchitectures[runtime.GOARCH]

	return arch, ok
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
