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
	"testing"

	"github.com/stretchr/testify/require"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func TestGoArchToSeccompArch(t *testing.T) {
	t.Parallel()

	for goArch, want := range map[string]seccompprofile.Arch{
		"386":     "SCMP_ARCH_X86",
		"amd64":   "SCMP_ARCH_X86_64",
		"arm64":   "SCMP_ARCH_AARCH64",
		"ppc64le": "SCMP_ARCH_PPC64LE",
		"s390x":   "SCMP_ARCH_S390X",
	} {
		arch, err := GoArchToSeccompArch(goArch)
		require.NoError(t, err)
		require.Equal(t, want, arch)
	}

	_, err := GoArchToSeccompArch("wasm")
	require.ErrorContains(t, err, "unsupported go arch provided: wasm")
}
