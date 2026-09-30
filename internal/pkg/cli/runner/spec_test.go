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

package runner

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func TestSpecFromCRD(t *testing.T) {
	t.Parallel()

	t.Run("seccomp profile", func(t *testing.T) {
		t.Parallel()

		content, err := specFromCRD([]byte(seccompProfileYAML +
			"  syscalls:\n  - action: SCMP_ACT_ALLOW\n    names: [read, write]\n"))
		require.NoError(t, err)

		spec := seccompprofileapi.SeccompProfileSpec{}
		require.NoError(t, json.Unmarshal(content, &spec))
		require.Equal(t, seccompprofileapi.ActErrno, spec.DefaultAction)
		require.Len(t, spec.Syscalls, 1)
		require.Equal(t, []string{"read", "write"}, spec.Syscalls[0].Names)

		// Only the spec is passed on, the object metadata is dropped.
		require.NotContains(t, string(content), "SeccompProfile")
	})

	t.Run("base profile", func(t *testing.T) {
		t.Parallel()

		_, err := specFromCRD(
			[]byte(seccompProfileYAML + "  baseProfileName: oci://registry/runc:v1\n"),
		)
		require.ErrorIs(t, err, ErrBaseProfile)
		require.ErrorContains(t, err, "oci://registry/runc:v1")
	})

	t.Run("other kind", func(t *testing.T) {
		t.Parallel()

		_, err := specFromCRD([]byte(
			"apiVersion: security-profiles-operator.x-k8s.io/v1\nkind: SelinuxProfile\nspec: {}\n",
		))
		require.ErrorContains(t, err, "expected a SeccompProfile, got SelinuxProfile")
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()

		_, err := specFromCRD([]byte("{"))
		require.ErrorContains(t, err, "unmarshal YAML profile")
	})
}
