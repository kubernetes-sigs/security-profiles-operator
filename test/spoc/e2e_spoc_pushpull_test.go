//go:build linux && !no_bpf

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

package main_test

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

// pushPullTest exercises spoc push and pull against an in-process OCI
// registry served over plain HTTP, so the round trip needs neither network
// access nor a public registry. Signing is skipped on both sides because
// keyless signing needs an OIDC identity.
func pushPullTest(t *testing.T) {
	server := httptest.NewServer(registry.New())
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")

	t.Run("runtime-spec seccomp profile", func(t *testing.T) {
		const profile = `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [{"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"}]
}
`

		in := writeTempFile(t, "profile.json", profile)
		ref := host + "/spoc/e2e/runtime:v1"

		_, err := runSpoc(t, "push", "--plain-http", "--disable-signing", "-f", in, ref)
		require.NoError(t, err, "push runtime-spec profile")

		out := filepath.Join(t.TempDir(), "pulled.json")
		_, err = runSpoc(t,
			"pull", "--plain-http", "--disable-signature-verification", "-o", out, ref,
		)
		require.NoError(t, err, "pull runtime-spec profile")

		pulled, err := os.ReadFile(out)
		require.NoError(t, err)
		require.JSONEq(t, profile, string(pulled),
			"runtime format content must round trip unchanged")
	})

	t.Run("profile CRD", func(t *testing.T) {
		crd := seccompprofileapi.SeccompProfile{
			Spec: seccompprofileapi.SeccompProfileSpec{
				DefaultAction: seccompprofileapi.ActErrno,
				Syscalls: []seccompprofileapi.Syscall{
					{Names: []string{"read", "write"}, Action: seccompprofileapi.ActAllow},
				},
			},
		}
		crd.APIVersion = seccompprofileapi.GroupVersion.String()
		crd.Kind = "SeccompProfile"
		crd.Name = "e2e"

		content, err := yaml.Marshal(crd)
		require.NoError(t, err)

		in := writeTempFile(t, "profile.yaml", string(content))
		ref := host + "/spoc/e2e/crd:v1"

		_, err = runSpoc(t, "push", "--plain-http", "--disable-signing", "-f", in, ref)
		require.NoError(t, err, "push profile CRD")

		out := filepath.Join(t.TempDir(), "pulled.yaml")
		_, err = runSpoc(t,
			"pull", "--plain-http", "--disable-signature-verification", "-o", out, ref,
		)
		require.NoError(t, err, "pull profile CRD")

		pulled, err := os.ReadFile(out)
		require.NoError(t, err)

		var got seccompprofileapi.SeccompProfile
		require.NoError(t, yaml.Unmarshal(pulled, &got))
		require.Equal(t, crd.Spec, got.Spec)
	})

	t.Run("push rejects what runtimes reject", func(t *testing.T) {
		const invalid = `{
  "defaultAction": "SCMP_ACT_ALLOW",
  "listenerPath": "/run/seccomp-listener.sock",
  "syscalls": [{"names": ["mount"], "action": "SCMP_ACT_NOTIFY"}]
}
`

		in := writeTempFile(t, "invalid.json", invalid)
		ref := host + "/spoc/e2e/invalid:v1"

		_, err := runSpoc(t, "push", "--plain-http", "--disable-signing", "-f", in, ref)
		require.Error(t, err, "a profile runtimes reject must not be pushed by default")

		_, err = runSpoc(t,
			"push", "--plain-http", "--disable-signing", "--disable-artifact-validation",
			"-f", in, ref,
		)
		require.NoError(t, err, "the opt-out publishes it anyway")
	})

	t.Run("identical content gets the same digest", func(t *testing.T) {
		const profile = `{"defaultAction": "SCMP_ACT_ERRNO"}` + "\n"

		in := writeTempFile(t, "profile.json", profile)

		first := pushAndDigest(t, in, host+"/spoc/e2e/stable:v1")
		second := pushAndDigest(t, in, host+"/spoc/e2e/stable:v2")
		require.Equal(t, first, second, "pushing the same content twice must not change the digest")
	})
}

// pushAndDigest pushes the file and returns the digest spoc logged for it.
func pushAndDigest(t *testing.T, file, ref string) string {
	t.Helper()

	out := runSpocOutput(t, "push", "--plain-http", "--disable-signing", "-f", file, ref)

	// The line looks like: Pushed artifact (reference=host/repo@sha256:...)
	const marker = "@sha256:"

	idx := strings.LastIndex(out, marker)
	require.NotEqual(t, -1, idx, "push output should log the pushed digest: %s", out)

	digest := out[idx+1:]
	if end := strings.IndexAny(digest, ")\" \n"); end != -1 {
		digest = digest[:end]
	}

	require.Len(t, digest, len("sha256:")+64, "unexpected digest %q", digest)

	return digest
}

// runSpocOutput runs spoc and returns its combined output.
func runSpocOutput(t *testing.T, args ...string) string {
	t.Helper()

	args = append([]string{spocPath}, args...)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	require.NoError(t, err, "failed to run spoc: %s", string(out))

	return string(out)
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	// spoc runs as root and can read the owner-only file.
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}
