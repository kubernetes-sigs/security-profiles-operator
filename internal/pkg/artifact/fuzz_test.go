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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzDecodeRuntimeSpecSeccompProfile feeds arbitrary artifact content into
// the runtime format decoding, which handles registry content before any
// signature constraint is applied by default. Accepted content has to be
// stable: encoding and decoding it again must not change it.
func FuzzDecodeRuntimeSpecSeccompProfile(f *testing.F) {
	for _, seed := range []string{
		rawSeccompJSON,
		rawSeccompArgJSON,
		`{"defaultAction":"SCMP_ACT_ERRNO"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"flags":["SCMP_FLTFLG_LOG"]}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","listenerPath":"/run/notify.sock"}`,
		`{"defaultAction":"SCMP_ACT_ERRNO"} {}`,
		`{"defaultAction":"SCMP_ACT_ERRNO","unknown":true}`,
		`{"syscalls":[]}`,
		`{}`,
		`[]`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		profile, err := decodeRuntimeSpecSeccompProfile(content)
		if err != nil {
			require.Nil(t, profile)

			return
		}

		require.NotEmpty(t, profile.DefaultAction)

		encoded, err := json.Marshal(profile)
		require.NoError(t, err)

		decoded, err := decodeRuntimeSpecSeccompProfile(encoded)
		require.NoError(t, err)

		again, err := json.Marshal(decoded)
		require.NoError(t, err)
		require.JSONEq(t, string(encoded), string(again))

		// The CRD conversion may reject values the CRD cannot hold, but has
		// to agree on the default action otherwise.
		spec, err := runtimeSpecSeccompProfileSpec(content)
		if err == nil {
			require.Equal(t, string(profile.DefaultAction), string(spec.DefaultAction))
		}
	})
}

// FuzzNameFromReference verifies that every reference results in a usable
// object name: not empty, only lower case alphanumerics, dots and dashes, and
// not starting or ending with a separator. The derivation is idempotent.
func FuzzNameFromReference(f *testing.F) {
	for _, seed := range []string{
		"",
		"registry.k8s.io/security-profiles-operator/base/runc:v1.5.1",
		"localhost:5000/Profile@sha256:0123456789abcdef",
		"ghcr.io/org/my__profile",
		"-.-",
		"a/b/c:d@e",
		"ÜBER/profile",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ref string) {
		profileName := nameFromReference(ref)
		require.NotEmpty(t, profileName)
		require.Regexp(t, `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`, profileName)
		require.Equal(t, profileName, nameFromReference(profileName))
	})
}
