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

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

// goArchToSeccompArch maps the values of runtime.GOARCH to the seccomp
// architectures.
var goArchToSeccompArch = map[string]seccompprofile.Arch{
	"386":         "SCMP_ARCH_X86",
	"amd64":       "SCMP_ARCH_X86_64",
	"amd64p32":    "SCMP_ARCH_X32",
	"arm":         "SCMP_ARCH_ARM",
	"arm64":       "SCMP_ARCH_AARCH64",
	"mips":        "SCMP_ARCH_MIPS",
	"mips64":      "SCMP_ARCH_MIPS64",
	"mips64le":    "SCMP_ARCH_MIPSEL64",
	"mips64p32":   "SCMP_ARCH_MIPS64N32",
	"mips64p32le": "SCMP_ARCH_MIPSEL64N32",
	"mipsle":      "SCMP_ARCH_MIPSEL",
	"ppc":         "SCMP_ARCH_PPC",
	"ppc64":       "SCMP_ARCH_PPC64",
	"ppc64le":     "SCMP_ARCH_PPC64LE",
	"s390":        "SCMP_ARCH_S390",
	"s390x":       "SCMP_ARCH_S390X",
}

// GoArchToSeccompArch converts a runtime.GOARCH to a seccomp architecture.
func GoArchToSeccompArch(goArch string) (seccompprofile.Arch, error) {
	arch, ok := goArchToSeccompArch[goArch]
	if !ok {
		return "", fmt.Errorf("unsupported go arch provided: %s", goArch)
	}

	return arch, nil
}
