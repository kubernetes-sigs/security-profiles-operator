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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// skipIfKubeletConfigExists skips tests that rely on the fallbacks used when
// the non-root enabler has not written a kubelet config, which is the case
// everywhere but on a node running the daemon.
func skipIfKubeletConfigExists(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(KubeletConfigFilePath()); err == nil {
		t.Skipf("%s exists on this host", KubeletConfigFilePath())
	}
}

func TestKubeletDir(t *testing.T) {
	skipIfKubeletConfigExists(t)

	for _, tc := range []struct {
		name string
		env  string
		want string
	}{
		{name: "default without env", env: "", want: DefaultKubeletPath},
		{name: "env overrides default", env: "/data/kubelet", want: "/data/kubelet"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(KubeletDirEnvKey, tc.env)

			require.Equal(t, tc.want, KubeletDir())
		})
	}
}

func TestProfilePaths(t *testing.T) {
	skipIfKubeletConfigExists(t)
	t.Setenv(KubeletDirEnvKey, "/data/kubelet")

	require.Equal(t, "/data/kubelet/seccomp", KubeletSeccompRootPath())
	require.Equal(t, "/data/kubelet/seccomp/operator", ProfilesRootPath())
}

func TestKubeletConfigFilePath(t *testing.T) {
	t.Parallel()

	require.Equal(
		t,
		"/var/lib/security-profiles-operator/kubelet-config.json",
		KubeletConfigFilePath(),
	)
}

func TestGetKubeletConfigFromFileMissing(t *testing.T) {
	t.Parallel()
	skipIfKubeletConfigExists(t)

	cfg, err := GetKubeletConfigFromFile()
	require.ErrorIs(t, err, os.ErrNotExist)
	require.ErrorContains(t, err, "reading kubelet config")
	require.Nil(t, cfg)
}

func TestGetOperatorNamespaceSet(t *testing.T) {
	t.Setenv(OperatorNamespaceEnvKey, "security-profiles-operator")

	require.Equal(t, "security-profiles-operator", GetOperatorNamespace())
}

func TestTryToGetOperatorNamespaceUnset(t *testing.T) {
	t.Setenv(OperatorNamespaceEnvKey, "")
	require.NoError(t, os.Unsetenv(OperatorNamespaceEnvKey))

	ns, err := TryToGetOperatorNamespace()
	require.ErrorIs(t, err, ErrPodNamespaceEnvNotFound)
	require.Empty(t, ns)
}
