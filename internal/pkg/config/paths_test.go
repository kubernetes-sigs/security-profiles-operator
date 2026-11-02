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

func TestKubeletDir(t *testing.T) {
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
	t.Setenv(KubeletDirEnvKey, "/data/kubelet")

	require.Equal(t, "/data/kubelet/seccomp", KubeletSeccompRootPath())
	require.Equal(t, "/data/kubelet/seccomp/operator", ProfilesRootPath())
}

func TestTryToGetOperatorNamespaceSet(t *testing.T) {
	t.Setenv(OperatorNamespaceEnvKey, "security-profiles-operator")

	ns, err := TryToGetOperatorNamespace()
	require.NoError(t, err)
	require.Equal(t, "security-profiles-operator", ns)
}

func TestTryToGetOperatorNamespaceUnset(t *testing.T) {
	t.Setenv(OperatorNamespaceEnvKey, "")
	require.NoError(t, os.Unsetenv(OperatorNamespaceEnvKey))

	ns, err := TryToGetOperatorNamespace()
	require.ErrorIs(t, err, ErrPodNamespaceEnvNotFound)
	require.Empty(t, ns)
}
