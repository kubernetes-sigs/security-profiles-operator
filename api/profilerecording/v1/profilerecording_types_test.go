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

package v1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func recording(kind ProfileRecordingKind, recorder ProfileRecorder) *ProfileRecording {
	return &ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "rec"},
		Spec:       ProfileRecordingSpec{Kind: kind, Recorder: recorder},
	}
}

func TestCtrAnnotation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		kind     ProfileRecordingKind
		recorder ProfileRecorder
		wantKey  string
		wantErr  bool
	}{
		{
			name: "seccomp logs", kind: ProfileRecordingKindSeccompProfile, recorder: ProfileRecorderLogs,
			wantKey: config.SeccompProfileRecordLogsAnnotationKey + "ctr",
		},
		{
			name: "seccomp bpf", kind: ProfileRecordingKindSeccompProfile, recorder: ProfileRecorderBpf,
			wantKey: config.SeccompProfileRecordBpfAnnotationKey + "ctr",
		},
		{name: "seccomp unknown recorder", kind: ProfileRecordingKindSeccompProfile, recorder: "Other", wantErr: true},
		{
			name: "selinux logs", kind: ProfileRecordingKindSelinuxProfile, recorder: ProfileRecorderLogs,
			wantKey: config.SelinuxProfileRecordLogsAnnotationKey + "ctr",
		},
		{name: "selinux bpf", kind: ProfileRecordingKindSelinuxProfile, recorder: ProfileRecorderBpf, wantErr: true},
		{name: "selinux unknown recorder", kind: ProfileRecordingKindSelinuxProfile, recorder: "Other", wantErr: true},
		{
			name: "apparmor bpf", kind: ProfileRecordingKindAppArmorProfile, recorder: ProfileRecorderBpf,
			wantKey: config.ApparmorProfileRecordBpfAnnotationKey + "ctr",
		},
		{name: "apparmor logs", kind: ProfileRecordingKindAppArmorProfile, recorder: ProfileRecorderLogs, wantErr: true},
		{name: "apparmor unknown recorder", kind: ProfileRecordingKindAppArmorProfile, recorder: "Other", wantErr: true},
		{name: "unknown kind", kind: "Other", recorder: ProfileRecorderBpf, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, value, err := recording(tc.kind, tc.recorder).CtrAnnotation("ctr")
			if tc.wantErr {
				require.Error(t, err)
				require.Empty(t, key)
				require.Empty(t, value)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantKey, key)

			// <recording>_<container>_<nonce>_<timestamp>
			parts := strings.Split(value, "_")
			require.Len(t, parts, 4, value)
			require.Equal(t, "rec", parts[0])
			require.Equal(t, "ctr", parts[1])
			require.Len(t, parts[2], 5)
			require.NotEmpty(t, parts[3])
		})
	}
}

func TestIsKindSupported(t *testing.T) {
	t.Parallel()

	for _, kind := range []ProfileRecordingKind{
		ProfileRecordingKindSeccompProfile,
		ProfileRecordingKindSelinuxProfile,
		ProfileRecordingKindAppArmorProfile,
	} {
		require.True(t, recording(kind, ProfileRecorderBpf).IsKindSupported(), kind)
	}

	require.False(t, recording("RawSelinuxProfile", ProfileRecorderBpf).IsKindSupported())
}

func TestValidateRecorderKindCombination(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		kind     ProfileRecordingKind
		recorder ProfileRecorder
		wantErr  bool
	}{
		{kind: ProfileRecordingKindSeccompProfile, recorder: ProfileRecorderLogs},
		{kind: ProfileRecordingKindSeccompProfile, recorder: ProfileRecorderBpf},
		{kind: ProfileRecordingKindSelinuxProfile, recorder: ProfileRecorderLogs},
		{kind: ProfileRecordingKindSelinuxProfile, recorder: ProfileRecorderBpf, wantErr: true},
		{kind: ProfileRecordingKindAppArmorProfile, recorder: ProfileRecorderBpf},
		{kind: ProfileRecordingKindAppArmorProfile, recorder: ProfileRecorderLogs, wantErr: true},
		{kind: "Other", recorder: ProfileRecorderBpf, wantErr: true},
	} {
		t.Run(string(tc.kind)+"/"+string(tc.recorder), func(t *testing.T) {
			t.Parallel()

			err := recording(tc.kind, tc.recorder).ValidateRecorderKindCombination()
			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}
