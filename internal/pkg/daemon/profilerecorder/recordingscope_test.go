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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"

	recordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

// recordingWebhookConfig returns a webhook configuration with a recording
// webhook of the selectors.
func recordingWebhookConfig(
	namespaceSelector, objectSelector *metav1.LabelSelector,
) *admissionregv1.MutatingWebhookConfiguration {
	return &admissionregv1.MutatingWebhookConfiguration{
		Webhooks: []admissionregv1.MutatingWebhook{
			{Name: "binding.spo.io"},
			{
				Name:              bindata.RecordingWebhookName,
				NamespaceSelector: namespaceSelector,
				ObjectSelector:    objectSelector,
			},
		},
	}
}

// TestRecordingEnabled asserts that the daemon accepts the recording
// annotations of the pods the deployed recording webhook applies to, and falls
// back to the webhook which the operator deploys for the SPOD.
func TestRecordingEnabled(t *testing.T) {
	t.Parallel()

	team := &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}
	web := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	teamOptions := &spodapi.SecurityProfilesOperatorDaemon{Spec: spodapi.SPODSpec{
		Webhook: spodapi.SPODWebhookConfig{Options: []spodapi.WebhookOptions{{
			Name:              bindata.RecordingWebhookName,
			NamespaceSelector: team,
		}}},
	}}
	staticTeamOptions := teamOptions.DeepCopy()
	staticTeamOptions.Spec.Webhook.StaticConfig = new(true)

	recordingLabel := map[string]string{bindata.EnableRecordingLabel: ""}
	teamLabel := map[string]string{"team": "a"}

	for name, tc := range map[string]struct {
		webhookConfig   *admissionregv1.MutatingWebhookConfiguration
		spod            *spodapi.SecurityProfilesOperatorDaemon
		namespaceLabels map[string]string
		podLabels       map[string]string
		want            bool
	}{
		"deployed namespace selector": {
			webhookConfig:   recordingWebhookConfig(team, nil),
			spod:            &spodapi.SecurityProfilesOperatorDaemon{},
			namespaceLabels: teamLabel,
			want:            true,
		},
		"deployed namespace selector over the SPOD": {
			webhookConfig:   recordingWebhookConfig(requireRecordingLabel(), nil),
			spod:            teamOptions,
			namespaceLabels: teamLabel,
		},
		"deployed object selector selects the pod": {
			webhookConfig:   recordingWebhookConfig(nil, web),
			namespaceLabels: map[string]string{},
			podLabels:       map[string]string{"app": "web"},
			want:            true,
		},
		"deployed object selector does not select the pod": {
			webhookConfig:   recordingWebhookConfig(nil, web),
			namespaceLabels: recordingLabel,
			podLabels:       map[string]string{"app": "db"},
		},
		"deployed configuration without recording webhook": {
			webhookConfig:   &admissionregv1.MutatingWebhookConfiguration{},
			namespaceLabels: recordingLabel,
		},
		"SPOD options": {
			spod:            teamOptions,
			namespaceLabels: teamLabel,
			want:            true,
		},
		"static configuration ignores the SPOD options": {
			spod:            staticTeamOptions,
			namespaceLabels: teamLabel,
		},
		"static configuration": {
			spod:            staticTeamOptions,
			namespaceLabels: recordingLabel,
			want:            true,
		},
		"default object selector excludes the operator pods": {
			namespaceLabels: recordingLabel,
			podLabels:       map[string]string{"name": "security-profiles-operator"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			mock.GetNamespaceReturns(&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "ns", Labels: tc.namespaceLabels},
			}, nil)

			if tc.webhookConfig != nil {
				mock.GetMutatingWebhookConfigurationReturns(tc.webhookConfig, nil)
			}

			if tc.spod != nil {
				mock.GetSPODReturns(tc.spod, nil)
			}

			sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "pod", Namespace: "ns", Labels: tc.podLabels,
			}}

			enabled, err := sut.recordingEnabled(t.Context(), pod)
			require.NoError(t, err)
			require.Equal(t, tc.want, enabled)

			_, _, configName := mock.GetMutatingWebhookConfigurationArgsForCall(0)
			require.Equal(t, bindata.MutatingWebhookConfigName, configName)

			// The SPOD is only read without a deployed configuration.
			if tc.webhookConfig != nil {
				require.Zero(t, mock.GetSPODCallCount())
			}
		})
	}
}

func requireRecordingLabel() *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: bindata.EnableRecordingLabel, Operator: metav1.LabelSelectorOpExists,
	}}}
}

// TestRecordingEnabledCaches asserts that the selectors of the recording
// webhook and the labels of a namespace are not read for every pod update.
func TestRecordingEnabledCaches(t *testing.T) {
	t.Parallel()

	mock := newFakeImpl()
	sut := &RecorderReconciler{impl: mock, log: logr.Discard()}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}}
	other := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "other"}}

	for range 3 {
		enabled, err := sut.recordingEnabled(t.Context(), pod)
		require.NoError(t, err)
		require.True(t, enabled)
	}

	require.Equal(t, 1, mock.GetMutatingWebhookConfigurationCallCount())
	require.Equal(t, 1, mock.GetSPODCallCount())
	require.Equal(t, 1, mock.GetNamespaceCallCount())

	// Every namespace has its own labels.
	_, err := sut.recordingEnabled(t.Context(), other)
	require.NoError(t, err)
	require.Equal(t, 2, mock.GetNamespaceCallCount())
	require.Equal(t, 1, mock.GetMutatingWebhookConfigurationCallCount())

	// They are read again once they expired.
	expiring := &RecorderReconciler{impl: mock, log: logr.Discard()}
	expiring.scope.ttl = time.Nanosecond

	for range 2 {
		_, err := expiring.recordingEnabled(t.Context(), pod)
		require.NoError(t, err)
	}

	require.Equal(t, 3, mock.GetMutatingWebhookConfigurationCallCount())
	require.Equal(t, 4, mock.GetNamespaceCallCount())
}

// TestRecordingEnabledWebhookReadErrors asserts that only a missing or
// forbidden webhook configuration falls back to the webhook of the SPOD. The
// selectors of the SPOD may not be the deployed ones, like with a static
// configuration, which would reject a pod for good on a transient error.
func TestRecordingEnabledWebhookReadErrors(t *testing.T) {
	t.Parallel()

	resource := admissionregv1.Resource("mutatingwebhookconfigurations")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}}

	for name, tc := range map[string]struct {
		err      error
		fallback bool
	}{
		"not found": {
			err:      kerrors.NewNotFound(resource, bindata.MutatingWebhookConfigName),
			fallback: true,
		},
		"forbidden": {
			err: kerrors.NewForbidden(
				resource, bindata.MutatingWebhookConfigName, errors.New("no access"),
			),
			fallback: true,
		},
		"unavailable": {
			err: kerrors.NewServiceUnavailable("unavailable"),
		},
		"timeout": {
			err: context.DeadlineExceeded,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			mock := newFakeImpl()
			mock.GetMutatingWebhookConfigurationReturns(nil, tc.err)

			sut := &RecorderReconciler{impl: mock, log: logr.Discard()}

			enabled, err := sut.recordingEnabled(t.Context(), pod)
			if tc.fallback {
				require.NoError(t, err)
				require.True(t, enabled)
				require.Equal(t, 1, mock.GetSPODCallCount())

				return
			}

			require.ErrorIs(t, err, tc.err)
			require.False(t, enabled)
			require.Zero(t, mock.GetSPODCallCount())

			// Nothing got cached, the next pod reads the configuration
			// again.
			mock.GetMutatingWebhookConfigurationReturns(
				recordingWebhookConfig(requireRecordingLabel(), nil), nil,
			)

			enabled, err = sut.recordingEnabled(t.Context(), pod)
			require.NoError(t, err)
			require.True(t, enabled)
			require.Equal(t, 2, mock.GetMutatingWebhookConfigurationCallCount())
		})
	}
}

// TestAuthorizedProfilesRereadsScopeOnFirstRejection asserts that a pod is not
// rejected for good because of a cached scope which is older than the pod,
// like the labels of a namespace which got labeled for recording right before
// the pod got created. Nothing looks at a rejected pod again unless it
// changes.
func TestAuthorizedProfilesRereadsScopeOnFirstRejection(t *testing.T) {
	t.Parallel()

	mock := newFakeImpl()
	mock.ListRecordingsReturns(&recordingapi.ProfileRecordingList{}, nil)
	mock.GetNamespaceReturns(&corev1.Namespace{}, nil)

	recorder := events.NewFakeRecorder(10)
	sut := &RecorderReconciler{impl: mock, log: logr.Discard(), record: recorder}

	profiles := []profileToCollect{{
		kind: recordingapi.ProfileRecordingKindSeccompProfile,
		name: "recording_ctr_4bbwm_1700000000",
	}}
	authorize := func(pod *corev1.Pod) {
		t.Helper()

		authorized, _, err := sut.authorizedProfiles(
			t.Context(), pod, profiles, recordingapi.ProfileRecorderBpf,
		)
		require.NoError(t, err)
		require.Empty(t, authorized)
	}

	// A pod of the namespace which is not labeled gets rejected.
	before := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "before", Namespace: "ns", UID: "1"}}
	authorize(before)
	require.Zero(t, mock.ListRecordingsCallCount())
	require.Len(t, recorder.Events, 1)
	<-recorder.Events

	namespaceReads := mock.GetNamespaceCallCount()

	// The updates of the rejected pod use the cached scope.
	authorize(before)
	require.Equal(t, namespaceReads, mock.GetNamespaceCallCount())
	require.Empty(t, recorder.Events)

	// The namespace gets labeled, the cached labels are stale. The first
	// rejection of a new pod reads them again, which enables the recording.
	mock.GetNamespaceReturns(recordingNamespace(), nil)

	after := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "after", Namespace: "ns", UID: "2"}}
	authorize(after)
	require.Equal(t, namespaceReads+1, mock.GetNamespaceCallCount())
	require.Equal(t, 1, mock.ListRecordingsCallCount(), "the recording is enabled")
}
