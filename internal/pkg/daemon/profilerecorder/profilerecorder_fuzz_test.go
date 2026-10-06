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

package profilerecorder

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// FuzzParseProfileAnnotation verifies that a parsed profile annotation
// consists of exactly the four underscore separated parts of the input.
func FuzzParseProfileAnnotation(f *testing.F) {
	for _, seed := range []string{
		"profile_container_nonce_1700000000",
		"my-recording_nginx_abc123_0",
		"___",
		"a_b_c",
		"a_b_c_d_e",
		"",
		"_",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, annotation string) {
		parsed, err := parseProfileAnnotation(annotation)
		if err != nil {
			require.Nil(t, parsed)

			return
		}

		parts := []string{parsed.profileName, parsed.cntName, parsed.nonce, parsed.timestamp}
		for _, part := range parts {
			require.NotContains(t, part, "_")
		}

		require.Equal(t, annotation, strings.Join(parts, "_"))
	})
}

// FuzzParseRecordingAnnotations feeds arbitrary pod annotations into the log
// and bpf recorder annotation parsing. Every annotation with a recording key
// prefix results in one profile to collect, in the order of the keys, and
// parsing fails exactly if one of them names no output profile.
func FuzzParseRecordingAnnotations(f *testing.F) {
	for _, seed := range []struct{ k1, v1, k2, v2 string }{
		{config.SeccompProfileRecordLogsAnnotationKey + "nginx", "profile_nginx_x_1", "other", "value"},
		{config.SelinuxProfileRecordLogsAnnotationKey + "nginx", "profile_nginx_x_1", "", ""},
		{config.SeccompProfileRecordBpfAnnotationKey + "nginx", "profile_nginx_x_1", "", ""},
		{
			config.ApparmorProfileRecordBpfAnnotationKey + "b", "b_b_b_b",
			config.SeccompProfileRecordBpfAnnotationKey + "a", "a_a_a_a",
		},
		{config.SeccompProfileRecordLogsAnnotationKey, "", "", ""},
		{config.SeccompProfileRecordBpfAnnotationKey + "x", "", "unrelated", ""},
	} {
		f.Add(seed.k1, seed.v1, seed.k2, seed.v2)
	}

	logKinds := map[string]profilerecordingapi.ProfileRecordingKind{
		config.SeccompProfileRecordLogsAnnotationKey: profilerecordingapi.ProfileRecordingKindSeccompProfile,
		config.SelinuxProfileRecordLogsAnnotationKey: profilerecordingapi.ProfileRecordingKindSelinuxProfile,
	}
	bpfKinds := map[string]profilerecordingapi.ProfileRecordingKind{
		config.SeccompProfileRecordBpfAnnotationKey:  profilerecordingapi.ProfileRecordingKindSeccompProfile,
		config.ApparmorProfileRecordBpfAnnotationKey: profilerecordingapi.ProfileRecordingKindAppArmorProfile,
	}

	f.Fuzz(func(t *testing.T, k1, v1, k2, v2 string) {
		annotations := map[string]string{k1: v1, k2: v2}

		logRes, logErr := parseLogAnnotations(annotations)
		checkParsedAnnotations(t, annotations, logKinds, logRes, logErr)

		bpfRes, bpfErr := parseBpfAnnotations(annotations)
		checkParsedAnnotations(t, annotations, bpfKinds, bpfRes, bpfErr)
	})
}

func checkParsedAnnotations(
	t *testing.T,
	annotations map[string]string,
	kinds map[string]profilerecordingapi.ProfileRecordingKind,
	res []profileToCollect,
	err error,
) {
	t.Helper()

	var want []profileToCollect

	missingProfile := false

	for _, key := range slices.Sorted(maps.Keys(annotations)) {
		for prefix, kind := range kinds {
			if !strings.HasPrefix(key, prefix) {
				continue
			}

			if annotations[key] == "" {
				missingProfile = true
			}

			want = append(want, profileToCollect{kind: kind, name: annotations[key]})

			break
		}
	}

	if missingProfile {
		require.ErrorIs(t, err, errInvalidAnnotation)
		require.Nil(t, res)

		return
	}

	require.NoError(t, err)
	require.Equal(t, want, res)
}

// FuzzCtxt2type verifies that the type of an SELinux context is its third
// colon separated field.
func FuzzCtxt2type(f *testing.F) {
	for _, seed := range []string{
		"system_u:system_r:container_t:s0:c1,c2",
		"system_u:object_r:var_log_t:s0",
		"a:b:c",
		"a:b",
		"::",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ctx string) {
		ctxType, err := ctxt2type(ctx)
		if err != nil {
			require.Empty(t, ctxType)
			require.Less(t, strings.Count(ctx, ":"), seContextRequiredParts-1)

			return
		}

		require.NotContains(t, ctxType, ":")
		require.Equal(t, strings.Split(ctx, ":")[2], ctxType)
	})
}
