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

package recording

import (
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

// eventRecorder returns a recorder together with the fake it records into.
func eventRecorder() (*podSeccompRecorder, *events.FakeRecorder) {
	fake := events.NewFakeRecorder(10)

	return &podSeccompRecorder{log: logr.Discard(), record: utils.NewSafeRecorder(fake)}, fake
}

// requireEvent asserts that exactly one event with the reason got recorded.
func requireEvent(t *testing.T, fake *events.FakeRecorder, reason string) {
	t.Helper()

	require.Len(t, fake.Events, 1)
	require.Contains(t, <-fake.Events, reason)
}

func logsRecording(
	kind profilerecordingapi.ProfileRecordingKind,
) *profilerecordingapi.ProfileRecording {
	return &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: "rec"},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     kind,
			Recorder: profilerecordingapi.ProfileRecorderLogs,
		},
	}
}

func TestUpdateSelinuxSecurityContext(t *testing.T) {
	t.Parallel()

	t.Run("without security context", func(t *testing.T) {
		t.Parallel()

		sut, fake := eventRecorder()
		ctr := &corev1.Container{Name: "container"}

		sut.updateSelinuxSecurityContext(
			ctr,
			logsRecording(profilerecordingapi.ProfileRecordingKindSelinuxProfile),
		)

		require.Equal(t,
			&corev1.SELinuxOptions{Type: config.SelinuxPermissiveProfile},
			ctr.SecurityContext.SELinuxOptions,
		)
		require.Empty(t, fake.Events)
	})

	t.Run("with existing options", func(t *testing.T) {
		t.Parallel()

		sut, fake := eventRecorder()
		ctr := &corev1.Container{
			Name: "container",
			SecurityContext: &corev1.SecurityContext{
				SELinuxOptions: &corev1.SELinuxOptions{Type: "other_t", Level: "s0:c1,c2"},
			},
		}

		sut.updateSelinuxSecurityContext(
			ctr,
			logsRecording(profilerecordingapi.ProfileRecordingKindSelinuxProfile),
		)

		// The type is overwritten, other fields such as the MCS level stay.
		require.Equal(t,
			&corev1.SELinuxOptions{Type: config.SelinuxPermissiveProfile, Level: "s0:c1,c2"},
			ctr.SecurityContext.SELinuxOptions,
		)
		requireEvent(t, fake, "SecurityContextAlreadySet")
	})

	// A reinvocation of the webhook finds the type it set itself, and options
	// without a type have nothing to overwrite.
	for name, opts := range map[string]*corev1.SELinuxOptions{
		"reinvocation":         {Type: config.SelinuxPermissiveProfile, Level: "s0:c1,c2"},
		"options without type": {Level: "s0:c1,c2"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut, fake := eventRecorder()
			ctr := &corev1.Container{
				Name:            "container",
				SecurityContext: &corev1.SecurityContext{SELinuxOptions: opts},
			}

			sut.updateSelinuxSecurityContext(
				ctr,
				logsRecording(profilerecordingapi.ProfileRecordingKindSelinuxProfile),
			)

			require.Equal(t,
				&corev1.SELinuxOptions{Type: config.SelinuxPermissiveProfile, Level: "s0:c1,c2"},
				ctr.SecurityContext.SELinuxOptions,
			)
			require.Empty(t, fake.Events)
		})
	}
}

func TestUpdateSeccompSecurityContextEvents(t *testing.T) {
	t.Parallel()

	rec := logsRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile)

	// The webhook sets the log enricher profile, and a reinvocation of the
	// webhook finds it.
	sut, fake := eventRecorder()
	ctr := &corev1.Container{Name: "container"}

	sut.updateSeccompSecurityContext(ctr, rec)
	require.Empty(t, fake.Events)

	set := ctr.SecurityContext.SeccompProfile.DeepCopy()

	sut.updateSeccompSecurityContext(ctr, rec)
	require.Empty(t, fake.Events)
	require.Equal(t, set, ctr.SecurityContext.SeccompProfile)

	// A profile of the pod author gets overwritten and reported.
	ctr.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeRuntimeDefault,
	}

	sut.updateSeccompSecurityContext(ctr, rec)
	requireEvent(t, fake, "SecurityContextAlreadySet")
	require.Equal(t, set, ctr.SecurityContext.SeccompProfile)
}

func TestUpdateSecurityContext(t *testing.T) {
	t.Parallel()

	t.Run("bpf recorder leaves the container alone", func(t *testing.T) {
		t.Parallel()

		sut, fake := eventRecorder()
		ctr := &corev1.Container{Name: "container"}
		rec := logsRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile)
		rec.Spec.Recorder = profilerecordingapi.ProfileRecorderBpf

		sut.updateSecurityContext(ctr, rec)

		require.Nil(t, ctr.SecurityContext)
		require.Empty(t, fake.Events)
	})

	t.Run("logs recorder sets the seccomp profile", func(t *testing.T) {
		t.Parallel()

		sut, _ := eventRecorder()
		ctr := &corev1.Container{Name: "container"}

		sut.updateSecurityContext(
			ctr,
			logsRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile),
		)

		require.NotNil(t, ctr.SecurityContext.SeccompProfile)
		require.Equal(
			t,
			corev1.SeccompProfileTypeLocalhost,
			ctr.SecurityContext.SeccompProfile.Type,
		)
	})
}

func TestWarnEventIfContainerPrivileged(t *testing.T) {
	t.Parallel()

	privileged := true
	// A pod of a workload has only a generate name on admission.
	const podName = "workload-"

	for _, tc := range []struct {
		name      string
		recorder  profilerecordingapi.ProfileRecorder
		ctr       *corev1.Container
		wantEvent bool
	}{
		{
			name:     "no security context",
			recorder: profilerecordingapi.ProfileRecorderLogs,
			ctr:      &corev1.Container{Name: "container"},
		},
		{
			name:     "not privileged",
			recorder: profilerecordingapi.ProfileRecorderLogs,
			ctr: &corev1.Container{
				Name:            "container",
				SecurityContext: &corev1.SecurityContext{Privileged: new(false)},
			},
		},
		{
			name:     "privileged with logs recorder",
			recorder: profilerecordingapi.ProfileRecorderLogs,
			ctr: &corev1.Container{
				Name:            "container",
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
			},
			wantEvent: true,
		},
		{
			name:     "privileged with bpf recorder",
			recorder: profilerecordingapi.ProfileRecorderBpf,
			ctr: &corev1.Container{
				Name:            "container",
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut, fake := eventRecorder()
			rec := logsRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile)
			rec.Spec.Recorder = tc.recorder

			sut.warnEventIfContainerPrivileged(rec, tc.ctr, podName)

			if tc.wantEvent {
				require.Len(t, fake.Events, 1)

				event := <-fake.Events
				require.Contains(t, event, "PrivilegedContainer")
				require.Contains(t, event, "pod "+podName)
				require.Contains(t, event, "bpf recorder")

				return
			}

			require.Empty(t, fake.Events)
		})
	}
}

// The recording name becomes a label value on the recorded profiles, which
// allows dots but limits the length to 63 characters.
func TestWarnEventIfNameTooLong(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		recording string
		wantEvent bool
	}{
		{name: "short", recording: "rec"},
		{name: "with dots", recording: "my.recording.example.com"},
		{name: "63 characters", recording: strings.Repeat("a", 63)},
		{name: "64 characters", recording: strings.Repeat("a", 64), wantEvent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sut, fake := eventRecorder()
			rec := logsRecording(profilerecordingapi.ProfileRecordingKindSeccompProfile)
			rec.Name = tc.recording

			sut.warnEventIfNameTooLong(rec)

			if tc.wantEvent {
				requireEvent(t, fake, "NameNotLabelValue")

				return
			}

			require.Empty(t, fake.Events)
		})
	}
}
