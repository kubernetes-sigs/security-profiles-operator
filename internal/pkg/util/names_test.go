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
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

func TestCheckRecordingOwner(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		resourceVersion string
		labels          map[string]string
		wantErr         bool
	}{
		{
			name: "new profile",
			labels: map[string]string{
				profilerecordingapi.ProfileToRecordingNamespaceLabel: "other",
			},
		},
		{
			name:            "existing profile without labels",
			resourceVersion: "1",
			wantErr:         true,
		},
		{
			name:            "existing profile with only the namespace label",
			resourceVersion: "1",
			labels: map[string]string{
				profilerecordingapi.ProfileToRecordingNamespaceLabel: "ns",
			},
			wantErr: true,
		},
		{
			name:            "existing profile recorded before the namespace label",
			resourceVersion: "1",
			labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel: "rec",
			},
		},
		{
			name:            "existing profile of the same recording",
			resourceVersion: "1",
			labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel:          "rec",
				profilerecordingapi.ProfileToRecordingNamespaceLabel: "ns",
			},
		},
		{
			name:            "existing profile of another namespace",
			resourceVersion: "1",
			labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel:          "rec",
				profilerecordingapi.ProfileToRecordingNamespaceLabel: "other",
			},
			wantErr: true,
		},
		{
			name:            "existing profile of another recording",
			resourceVersion: "1",
			labels: map[string]string{
				profilerecordingapi.ProfileToRecordingLabel:          "other",
				profilerecordingapi.ProfileToRecordingNamespaceLabel: "ns",
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profile := &seccompprofile.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "rec-ctr",
					ResourceVersion: tc.resourceVersion,
					Labels:          tc.labels,
				},
			}

			err := CheckRecordingOwner(profile, "rec", "ns")
			if tc.wantErr {
				require.ErrorIs(t, err, ErrProfileOwnedByOtherRecording)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLengthName(t *testing.T) {
	t.Parallel()

	const maxLen = 20

	t.Run("a fitting name is returned as is", func(t *testing.T) {
		t.Parallel()

		got, err := lengthName(maxLen, "prefix", "%s-%s", "short", "name")
		require.NoError(t, err)
		require.Equal(t, "short-name", got)
	})

	t.Run("a name of exactly the limit is hashed", func(t *testing.T) {
		t.Parallel()

		// Documented off-by-one: the threshold is part of the persisted
		// naming scheme of the node statuses.
		name := strings.Repeat("n", maxLen)

		got, err := lengthName(maxLen, "p", "%s", name)
		require.NoError(t, err)
		require.NotEqual(t, name, got)
		require.Len(t, got, maxLen)
	})

	t.Run("a long name is replaced by the prefix and a hash", func(t *testing.T) {
		t.Parallel()

		name := strings.Repeat("n", 100)

		got, err := lengthName(maxLen, "prefix", "%s", name)
		require.NoError(t, err)
		require.Len(t, got, maxLen)
		require.True(t, strings.HasPrefix(got, "prefix-"))

		again, err := lengthName(maxLen, "prefix", "%s", name)
		require.NoError(t, err)
		require.Equal(t, got, again, "hashing is deterministic")

		other, err := lengthName(maxLen, "prefix", "%s", name+"x")
		require.NoError(t, err)
		require.NotEqual(t, got, other, "different names get different hashes")
	})

	t.Run("a limit beyond the hash length keeps the whole hash", func(t *testing.T) {
		t.Parallel()

		name := strings.Repeat("n", 300)

		got, err := lengthName(200, "prefix", "%s", name)
		require.NoError(t, err)
		require.Len(t, got, len("prefix-")+sha256.Size*2)
	})

	t.Run("a prefix without room for the hash fails", func(t *testing.T) {
		t.Parallel()

		_, err := lengthName(maxLen, strings.Repeat("p", maxLen), "%s", strings.Repeat("n", 100))
		require.ErrorContains(t, err, "shortening string")
	})
}

func TestDNSLengthName(t *testing.T) {
	t.Parallel()

	require.Equal(t, "kind-name", DNSLengthName("kind", "%s-%s", "kind", "name"))

	long := DNSLengthName("kind", "%s-%s", "kind", strings.Repeat("n", 100))
	require.Len(t, long, validation.DNS1123LabelMaxLength)
	require.True(t, strings.HasPrefix(long, "kind-"))
	require.Empty(t, validation.IsDNS1123Label(long))

	// The error of lengthName is swallowed.
	require.Empty(t, DNSLengthName(
		strings.Repeat("p", validation.DNS1123LabelMaxLength), "%s", strings.Repeat("n", 100),
	))
}

func TestKindNameDNSLengthName(t *testing.T) {
	t.Parallel()

	require.Equal(t, "SeccompProfile-name", KindNameDNSLengthName("SeccompProfile", "name"))
	require.Equal(t,
		"SeccompProfile-9d42ecd8a72de861cc202ee69381e536088eec6dc43f8f8e",
		KindNameDNSLengthName(
			"SeccompProfile",
			"this-is-a-very-long-name-surely-over-64-characters-omg-its-overflowing",
		),
	)
}

func TestNameHashing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		prof      seccompprofile.SeccompProfile
		labelName string
	}{
		{
			name: "short name",
			prof: seccompprofile.SeccompProfile{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SeccompProfile",
					APIVersion: "security-profiles-operator.x-k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shortname-profile",
					Namespace: "security-profiles-operator",
				},
				Spec:   seccompprofile.SeccompProfileSpec{},
				Status: seccompprofile.SeccompProfileStatus{},
			},
			labelName: "SeccompProfile-shortname-profile",
		},
		{
			name: "long name",
			prof: seccompprofile.SeccompProfile{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SeccompProfile",
					APIVersion: "security-profiles-operator.x-k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "this-is-a-very-long-name-surely-over-64-characters-omg-its-overflowing",
					Namespace: "security-profiles-operator",
				},
				Spec:   seccompprofile.SeccompProfileSpec{},
				Status: seccompprofile.SeccompProfileStatus{},
			},
			labelName: "SeccompProfile-9d42ecd8a72de861cc202ee69381e536088eec6dc43f8f8e",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			name := KindNameDNSLengthName(tc.prof.Kind, tc.prof.Name)
			require.Equal(t, tc.labelName, name)
		})
	}
}
