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

package artifact

import (
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

const SeccompProfileExample = `
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - foo
`

const SelinuxProfileExample = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: SelinuxProfile
spec:
  inherit:
    - name: container
  allow:
    var_log_t:
      dir:
        - open
`

const AppArmorProfileExample = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: AppArmorProfile
spec:
  abstract:
    filesystem:
      readOnlyPaths:
      - /dev/null
`

func TestReadProfile(t *testing.T) {
	t.Parallel()
	t.Run("AppArmor", func(t *testing.T) {
		t.Parallel()

		profile, err := ReadProfile([]byte(AppArmorProfileExample))
		require.NoError(t, err)
		require.IsType(t, &apparmorprofileapi.AppArmorProfile{}, profile)
	})
	t.Run("SELinux", func(t *testing.T) {
		t.Parallel()

		profile, err := ReadProfile([]byte(SelinuxProfileExample))
		require.NoError(t, err)
		require.IsType(t, &selinuxprofileapi.SelinuxProfile{}, profile)
	})
	t.Run("seccomp", func(t *testing.T) {
		t.Parallel()

		profile, err := ReadProfile([]byte(SeccompProfileExample))
		require.NoError(t, err)
		require.IsType(t, &seccompprofile.SeccompProfile{}, profile)
	})

	t.Run("invalid file", func(t *testing.T) {
		t.Parallel()

		_, err := ReadProfile([]byte("\x00"))
		require.ErrorContains(t, err, "cannot parse yaml")
	})

	t.Run("invalid yaml", func(t *testing.T) {
		t.Parallel()

		_, err := ReadProfile([]byte("{}"))
		require.ErrorContains(t, err, "kind missing")
	})

	t.Run("unknown kind", func(t *testing.T) {
		t.Parallel()

		_, err := ReadProfile([]byte("kind: unknown"))
		require.ErrorContains(t, err, "unexpected YAML kind")
	})
}
