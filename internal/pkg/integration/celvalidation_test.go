//go:build integration

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

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// The tests of this file assert the CEL validation rules of the CRDs in a
// real API server, like TestSPODValidation does for the SPOD.

// requireCreate creates the object and asserts that the API server rejects it
// with an error containing wantErr, or accepts it if wantErr is empty. An
// accepted object gets deleted at the end of the test, also one which should
// have been rejected, so that the controllers of the other tests do not pick
// it up for long and a repeated run does not find it.
func requireCreate(t *testing.T, obj client.Object, wantErr string) {
	t.Helper()

	err := k8sClient.Create(t.Context(), obj)
	if err == nil {
		t.Cleanup(func() { requireDeleted(t, obj) })
	}

	if wantErr == "" {
		require.NoError(t, err)

		return
	}

	requireInvalid(t, err, wantErr)
}

// requireInvalid asserts that err is a validation error containing wantErr.
func requireInvalid(t *testing.T, err error, wantErr string) {
	t.Helper()

	require.True(t, apierrors.IsInvalid(err), "unexpected error: %v", err)
	require.ErrorContains(t, err, wantErr)
}

// requireDeleted deletes the object, which may be gone already. It runs as
// cleanup, when the context of the test is canceled already.
func requireDeleted(t *testing.T, obj client.Object) {
	t.Helper()

	require.NoError(t, client.IgnoreNotFound(k8sClient.Delete(context.Background(), obj)))
}

// selectorCases are label selectors for the matchExpressions rule of the
// selector fields, invalid if the rule rejects them.
var selectorCases = []struct {
	name     string
	selector *metav1.LabelSelector
	invalid  bool
}{
	{
		name:     "empty selector",
		selector: &metav1.LabelSelector{},
	},
	{
		name: "In with values",
		selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"nginx"},
		}}},
	},
	{
		name: "DoesNotExist without values",
		selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: metav1.LabelSelectorOpDoesNotExist,
		}}},
	},
	{
		name: "NotIn without values",
		selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: metav1.LabelSelectorOpNotIn,
		}}},
		invalid: true,
	},
	{
		name: "Exists with values",
		selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: metav1.LabelSelectorOpExists, Values: []string{"nginx"},
		}}},
		invalid: true,
	},
	{
		name: "unknown operator",
		selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "app", Operator: "Equals", Values: []string{"nginx"},
		}}},
		invalid: true,
	},
}

// selectorErr is the message of the matchExpressions rule.
const selectorErr = "matchExpressions operator must be In, NotIn, Exists or DoesNotExist"

func TestSeccompProfileValidation(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	for _, tc := range []struct {
		name    string
		mutate  func(*seccompprofileapi.SeccompProfileSpec)
		wantErr string
	}{
		{
			name:   "no base profile",
			mutate: func(*seccompprofileapi.SeccompProfileSpec) {},
		},
		{
			name: "base profile name",
			mutate: func(spec *seccompprofileapi.SeccompProfileSpec) {
				spec.BaseProfileName = "runc-v1.3.0"
			},
		},
		{
			name: "base profile oci reference",
			mutate: func(spec *seccompprofileapi.SeccompProfileSpec) {
				spec.BaseProfileName = "oci://ghcr.io/security-profiles/runc:v1.3.0"
			},
		},
		{
			name: "base profile name with uppercase letters",
			mutate: func(spec *seccompprofileapi.SeccompProfileSpec) {
				spec.BaseProfileName = "Runc"
			},
			wantErr: "baseProfileName must be an oci:// reference or the name of a SeccompProfile",
		},
		{
			name: "base profile name with a path",
			mutate: func(spec *seccompprofileapi.SeccompProfileSpec) {
				spec.BaseProfileName = "ghcr.io/security-profiles/runc"
			},
			wantErr: "baseProfileName must be an oci:// reference or the name of a SeccompProfile",
		},
		{
			name: "notify as default action",
			mutate: func(spec *seccompprofileapi.SeccompProfileSpec) {
				spec.DefaultAction = seccompprofileapi.ActNotify
			},
			wantErr: "SCMP_ACT_NOTIFY cannot be used as the default action",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profile := &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "cel-seccomp-"},
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccompprofileapi.ActErrno,
				},
			}
			tc.mutate(&profile.Spec)

			requireCreate(t, profile, tc.wantErr)
		})
	}
}

func TestSelinuxProfileValidation(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	for _, tc := range []struct {
		name    string
		objName string
		allow   selinuxprofileapi.Allow
		wantErr string
		// raw checks a RawSelinuxProfile of the name as well, which shares
		// the name rule, since its name is the name of the CIL block too.
		raw bool
	}{
		{
			name:    "valid",
			objName: "cel-selinux-valid",
			raw:     true,
			allow: selinuxprofileapi.Allow{
				"@self":         {"tcp_socket": {"listen"}},
				"var_log_t":     {"file": {"open", "read"}},
				"container_t.x": {"dir": {"search"}},
			},
		},
		{
			name:    "name starting with a digit",
			objName: "1-cel-selinux",
			raw:     true,
			wantErr: "name must start with a letter",
		},
		{
			name:    "name with a dot",
			objName: "cel.selinux",
			raw:     true,
			wantErr: "name must start with a letter",
		},
		{
			name:    "type with a parenthesis",
			objName: "cel-selinux-type",
			allow:   selinuxprofileapi.Allow{"var_log_t)": {"file": {"read"}}},
			wantErr: "types may only contain alphanumeric characters",
		},
		{
			name:    "self with a suffix",
			objName: "cel-selinux-self",
			allow:   selinuxprofileapi.Allow{"@self_t": {"file": {"read"}}},
			wantErr: "types may only contain alphanumeric characters",
		},
		{
			name:    "class with a space",
			objName: "cel-selinux-class",
			allow:   selinuxprofileapi.Allow{"var_log_t": {"file read": {"read"}}},
			wantErr: "object classes may only contain alphanumeric characters",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requireCreate(t, &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: tc.objName},
				Spec:       selinuxprofileapi.SelinuxProfileSpec{Allow: tc.allow},
			}, tc.wantErr)

			if !tc.raw {
				return
			}

			requireCreate(t, &selinuxprofileapi.RawSelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: tc.objName},
				Spec: selinuxprofileapi.RawSelinuxProfileSpec{
					Policy: "(blockinherit container)",
				},
			}, tc.wantErr)
		})
	}
}

func TestProfileRecordingValidation(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	namespace := newNamespace(t)

	newRecording := func(
		name string, kind profilerecordingapi.ProfileRecordingKind, recorder profilerecordingapi.ProfileRecorder,
	) *profilerecordingapi.ProfileRecording {
		return &profilerecordingapi.ProfileRecording{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: profilerecordingapi.ProfileRecordingSpec{
				Kind:        kind,
				Recorder:    recorder,
				PodSelector: &metav1.LabelSelector{},
			},
		}
	}

	for _, tc := range []struct {
		name      string
		recording *profilerecordingapi.ProfileRecording
		wantErr   string
	}{
		{
			name: "seccomp with logs",
			recording: newRecording("seccomp-logs",
				profilerecordingapi.ProfileRecordingKindSeccompProfile, profilerecordingapi.ProfileRecorderLogs),
		},
		{
			name: "seccomp with bpf",
			recording: newRecording("seccomp-bpf",
				profilerecordingapi.ProfileRecordingKindSeccompProfile, profilerecordingapi.ProfileRecorderBpf),
		},
		{
			name: "selinux with logs",
			recording: newRecording("selinux-logs",
				profilerecordingapi.ProfileRecordingKindSelinuxProfile, profilerecordingapi.ProfileRecorderLogs),
		},
		{
			name: "selinux with bpf",
			recording: newRecording("selinux-bpf",
				profilerecordingapi.ProfileRecordingKindSelinuxProfile, profilerecordingapi.ProfileRecorderBpf),
			wantErr: "SelinuxProfile recordings only support the Logs recorder",
		},
		{
			name: "apparmor with bpf",
			recording: newRecording("apparmor-bpf",
				profilerecordingapi.ProfileRecordingKindAppArmorProfile, profilerecordingapi.ProfileRecorderBpf),
		},
		{
			name: "apparmor with logs",
			recording: newRecording("apparmor-logs",
				profilerecordingapi.ProfileRecordingKindAppArmorProfile, profilerecordingapi.ProfileRecorderLogs),
			wantErr: "AppArmorProfile recordings only support the Bpf recorder",
		},
		{
			name: "name of 63 characters",
			recording: newRecording(strings.Repeat("a", 63),
				profilerecordingapi.ProfileRecordingKindSeccompProfile, profilerecordingapi.ProfileRecorderLogs),
		},
		{
			name: "name of 64 characters",
			recording: newRecording(strings.Repeat("a", 64),
				profilerecordingapi.ProfileRecordingKindSeccompProfile, profilerecordingapi.ProfileRecorderLogs),
			wantErr: "name must be no more than 63 characters",
		},
		{
			name: "seccomp name with a dot",
			recording: newRecording("seccomp.dot",
				profilerecordingapi.ProfileRecordingKindSeccompProfile, profilerecordingapi.ProfileRecorderLogs),
		},
		{
			name: "selinux name with a dot",
			recording: newRecording("selinux.dot",
				profilerecordingapi.ProfileRecordingKindSelinuxProfile, profilerecordingapi.ProfileRecorderLogs),
			wantErr: "the name of a SelinuxProfile recording must start with a letter",
		},
		{
			name: "selinux name starting with a digit",
			recording: newRecording("1-selinux",
				profilerecordingapi.ProfileRecordingKindSelinuxProfile, profilerecordingapi.ProfileRecorderLogs),
			wantErr: "the name of a SelinuxProfile recording must start with a letter",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requireCreate(t, tc.recording, tc.wantErr)
		})
	}

	for i, tc := range selectorCases {
		t.Run("pod selector "+tc.name, func(t *testing.T) {
			t.Parallel()

			recording := newRecording(
				"selector-"+strings.Repeat("a", i+1),
				profilerecordingapi.ProfileRecordingKindSeccompProfile,
				profilerecordingapi.ProfileRecorderLogs,
			)
			recording.Spec.PodSelector = tc.selector

			wantErr := ""
			if tc.invalid {
				wantErr = selectorErr
			}

			requireCreate(t, recording, wantErr)
		})
	}

	// The name rule of SelinuxProfile recordings exempts the recordings
	// which were SelinuxProfile recordings before, but not the ones which
	// turn into one.
	t.Run("update to a selinux recording with an invalid name", func(t *testing.T) {
		t.Parallel()

		recording := newRecording(
			"1-seccomp",
			profilerecordingapi.ProfileRecordingKindSeccompProfile,
			profilerecordingapi.ProfileRecorderLogs,
		)
		requireCreate(t, recording, "")

		recording.Spec.Kind = profilerecordingapi.ProfileRecordingKindSelinuxProfile
		requireInvalid(t, k8sClient.Update(t.Context(), recording),
			"the name of a SelinuxProfile recording must start with a letter")
	})

	t.Run("update of a recording with a valid name", func(t *testing.T) {
		t.Parallel()

		recording := newRecording(
			"selinux-update",
			profilerecordingapi.ProfileRecordingKindSelinuxProfile,
			profilerecordingapi.ProfileRecorderLogs,
		)
		requireCreate(t, recording, "")

		recording.Spec.Containers = []string{"nginx"}
		require.NoError(t, k8sClient.Update(t.Context(), recording))
	})
}

func TestProfileBindingValidation(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	namespace := newNamespace(t)

	for _, tc := range selectorCases {
		t.Run("pod selector "+tc.name, func(t *testing.T) {
			t.Parallel()

			wantErr := ""
			if tc.invalid {
				wantErr = selectorErr
			}

			requireCreate(t, &profilebindingapi.ProfileBinding{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "cel-binding-", Namespace: namespace},
				Spec: profilebindingapi.ProfileBindingSpec{
					ProfileRef: profilebindingapi.ProfileRef{
						Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
						Name: "profile",
					},
					Image:       "*",
					PodSelector: tc.selector,
				},
			}, wantErr)
		})
	}
}

func TestSecurityProfileNodeStatusValidation(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "cel-node-status-"},
		Spec:       secprofnodestatusapi.SecurityProfileNodeStatusSpec{NodeName: "cel-node-1"},
	}
	requireCreate(t, status, "")

	// Updates which keep the node name pass the rule.
	status.Labels = map[string]string{"cel": "true"}
	require.NoError(t, k8sClient.Update(t.Context(), status))

	status.Spec.NodeName = "cel-node-2"
	requireInvalid(t, k8sClient.Update(t.Context(), status), "nodeName is immutable")
}
