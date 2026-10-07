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

package artifact

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// A broken docker config, like a credential helper missing from the PATH,
// falls back to anonymous access, while explicit credentials are used as they
// are.
func TestSetRepoCredentials(t *testing.T) {
	dockerConfig := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dockerConfig, "config.json"),
		[]byte(`{"credsStore": "spo-missing-helper"}`),
		0o600,
	))
	t.Setenv("DOCKER_CONFIG", dockerConfig)

	const registry = "registry.example.com"

	credentialOf := func(username, password string) auth.Credential {
		t.Helper()

		repo, err := remote.NewRepository(registry + "/profile")
		require.NoError(t, err)

		New(logr.Discard()).setRepoCredentials(repo, username, password)

		client, ok := repo.Client.(*auth.Client)
		require.True(t, ok)

		credential, err := client.Credential(t.Context(), registry)
		require.NoError(t, err)

		return credential
	}

	require.Equal(t, auth.EmptyCredential, credentialOf("", ""))
	require.Equal(t,
		auth.Credential{Username: "user", Password: "pass"},
		credentialOf("user", "pass"),
	)
}
