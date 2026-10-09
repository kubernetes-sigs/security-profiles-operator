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

package recordingtracker

import (
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func TestRecordingStatusReportsKindAndRecorder(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		kind       profilerecordingapi.ProfileRecordingKind
		recorder   profilerecordingapi.ProfileRecorder
		wantReason common.ConditionReason
	}{
		"seccomp with bpf": {
			kind:       profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			wantReason: common.ReasonAvailable,
		},
		"selinux with bpf": {
			kind:       profilerecordingapi.ProfileRecordingKindSelinuxProfile,
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			wantReason: common.ReasonUnavailable,
		},
		"apparmor with logs": {
			kind:       profilerecordingapi.ProfileRecordingKindAppArmorProfile,
			recorder:   profilerecordingapi.ProfileRecorderLogs,
			wantReason: common.ReasonUnavailable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recording := &profilerecordingapi.ProfileRecording{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "recording",
					Namespace:  "default",
					Generation: 3,
				},
				Spec: profilerecordingapi.ProfileRecordingSpec{
					Kind:     tc.kind,
					Recorder: tc.recorder,
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(utiltest.NewScheme(t)).
				WithStatusSubresource(recording).
				WithObjects(recording).
				Build()

			r := &recordingStatusReconciler{client: c, reader: c, log: logr.Discard()}

			_, err := r.Reconcile(t.Context(), reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(recording),
			})
			require.NoError(t, err)

			updated := &profilerecordingapi.ProfileRecording{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))

			ready := updated.Status.GetReadyCondition()
			require.Equal(t, string(tc.wantReason), ready.Reason)
			require.Equal(t, updated.Generation, ready.ObservedGeneration)
		})
	}
}

const testOperatorNamespace = "security-profiles-operator"

// statusRecording returns a seccomp recording in the default namespace.
func statusRecording(
	recorder profilerecordingapi.ProfileRecorder,
) *profilerecordingapi.ProfileRecording {
	return &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "recording",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:     profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder: recorder,
		},
	}
}

// spod returns a SPOD in the operator namespace which enables the recorders.
func spod(name string, logEnricher, bpfRecorder bool) *spodapi.SecurityProfilesOperatorDaemon {
	return &spodapi.SecurityProfilesOperatorDaemon{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testOperatorNamespace},
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{
				EnableLogEnricher: &logEnricher,
				EnableBpfRecorder: &bpfRecorder,
			},
		},
	}
}

// webhookConfig returns the mutating webhook configuration with the recording
// webhook selecting the namespaces.
func webhookConfig(selector *metav1.LabelSelector) *admissionregv1.MutatingWebhookConfiguration {
	return &admissionregv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: bindata.MutatingWebhookConfigName},
		Webhooks: []admissionregv1.MutatingWebhook{
			{Name: "binding.spo.io"},
			{Name: bindata.RecordingWebhookName, NamespaceSelector: selector},
		},
	}
}

func namespaceObject(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// reconcileStatus reconciles the status of the recording and returns its
// conditions.
func reconcileStatus(
	t *testing.T,
	env recorderEnv,
	recording *profilerecordingapi.ProfileRecording,
	objs ...client.Object,
) (ready, conflict metav1.Condition) {
	t.Helper()

	// Parallel subtests share some objects, which the fake client sets the
	// resource version on.
	copies := make([]client.Object, 0, len(objs)+1)
	for _, obj := range objs {
		cp, ok := obj.DeepCopyObject().(client.Object)
		require.True(t, ok)

		copies = append(copies, cp)
	}

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithStatusSubresource(recording).
		WithObjects(append(copies, recording)...).
		Build()

	r := &recordingStatusReconciler{
		client:            c,
		reader:            c,
		log:               logr.Discard(),
		operatorNamespace: testOperatorNamespace,
		env:               env,
	}

	_, err := r.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(recording),
	})
	require.NoError(t, err)

	updated := &profilerecordingapi.ProfileRecording{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))

	for _, condition := range updated.Status.Conditions {
		if condition.Type == string(profilerecordingapi.ConditionTypeProfileConflict) {
			conflict = condition
		}
	}

	return updated.Status.GetReadyCondition(), conflict
}

func TestRecordingStatusReportsDisabledRecorder(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		recorder   profilerecordingapi.ProfileRecorder
		env        recorderEnv
		spods      []client.Object
		wantReason common.ConditionReason
	}{
		"bpf disabled": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			spods:      []client.Object{spod("spod", true, false)},
			wantReason: profilerecordingapi.ReasonRecorderDisabled,
		},
		"logs disabled": {
			recorder:   profilerecordingapi.ProfileRecorderLogs,
			spods:      []client.Object{spod("spod", false, true)},
			wantReason: profilerecordingapi.ReasonRecorderDisabled,
		},
		"bpf enabled": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			spods:      []client.Object{spod("spod", false, true)},
			wantReason: common.ReasonAvailable,
		},
		// The daemons only follow the SPOD named spod.
		"bpf enabled by another spod": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			spods:      []client.Object{spod("spod", false, false), spod("other", false, true)},
			wantReason: profilerecordingapi.ReasonRecorderDisabled,
		},
		"only another spod enables bpf": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			spods:      []client.Object{spod("other", false, true)},
			wantReason: common.ReasonAvailable,
		},
		"only another spod disables bpf": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			spods:      []client.Object{spod("other", false, false)},
			wantReason: common.ReasonAvailable,
		},
		"bpf enabled by the environment": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			env:        recorderEnv{bpfRecorder: true},
			spods:      []client.Object{spod("spod", false, false)},
			wantReason: common.ReasonAvailable,
		},
		"logs enabled by the environment": {
			recorder:   profilerecordingapi.ProfileRecorderLogs,
			env:        recorderEnv{logEnricher: true},
			spods:      []client.Object{spod("spod", false, false)},
			wantReason: common.ReasonAvailable,
		},
		"no spod": {
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			wantReason: common.ReasonAvailable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ready, _ := reconcileStatus(t, tc.env, statusRecording(tc.recorder), tc.spods...)
			require.Equal(t, string(tc.wantReason), ready.Reason)

			if tc.wantReason == profilerecordingapi.ReasonRecorderDisabled {
				require.Equal(t, metav1.ConditionFalse, ready.Status)
				require.Contains(t, ready.Message, "spec.enricher.enable")
			}
		})
	}
}

func TestRecordingStatusReportsNamespaceNotEnabled(t *testing.T) {
	t.Parallel()

	requireLabel := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      bindata.EnableRecordingLabel,
			Operator: metav1.LabelSelectorOpExists,
		}},
	}

	for name, tc := range map[string]struct {
		objs       []client.Object
		wantReason common.ConditionReason
	}{
		"namespace without label": {
			objs: []client.Object{
				webhookConfig(requireLabel), namespaceObject("default", nil),
			},
			wantReason: profilerecordingapi.ReasonNamespaceNotEnabled,
		},
		"namespace with label": {
			objs: []client.Object{
				webhookConfig(requireLabel),
				namespaceObject("default", map[string]string{bindata.EnableRecordingLabel: ""}),
			},
			wantReason: common.ReasonAvailable,
		},
		"webhook selects all namespaces": {
			objs:       []client.Object{webhookConfig(nil), namespaceObject("default", nil)},
			wantReason: common.ReasonAvailable,
		},
		"no webhook configuration": {
			objs:       []client.Object{namespaceObject("default", nil)},
			wantReason: common.ReasonAvailable,
		},
		"disabled recorder takes precedence": {
			objs: []client.Object{
				spod("spod", false, false), webhookConfig(requireLabel), namespaceObject("default", nil),
			},
			wantReason: profilerecordingapi.ReasonRecorderDisabled,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ready, _ := reconcileStatus(
				t,
				recorderEnv{},
				statusRecording(profilerecordingapi.ProfileRecorderBpf),
				tc.objs...,
			)
			require.Equal(t, string(tc.wantReason), ready.Reason)
		})
	}
}

// seccompProfile returns a cluster scoped seccomp profile with the labels.
func seccompProfile(name string, labels map[string]string) *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActErrno,
		},
	}
}

// recordedBy returns the labels of a profile recorded by the recording named
// "recording" in the namespace.
func recordedBy(namespace string) map[string]string {
	return map[string]string{
		profilerecordingapi.ProfileToRecordingLabel:          "recording",
		profilerecordingapi.ProfileToRecordingNamespaceLabel: namespace,
	}
}

func TestRecordingStatusReportsProfileConflicts(t *testing.T) {
	t.Parallel()

	// A pod of a replicating controller, whose nginx container gets recorded.
	replica := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:         "app-abcde",
			GenerateName: "app-",
			Namespace:    "default",
			Annotations: map[string]string{
				config.SeccompProfileRecordBpfAnnotationKey + "nginx": "recording_nginx_12345_1",
				config.SeccompProfileRecordBpfAnnotationKey + "other": "other_other_12345_1",
			},
		},
	}

	partial := seccompProfile("recording-redis-xyz", map[string]string{
		profilerecordingapi.ProfileToRecordingLabel:          "recording",
		profilerecordingapi.ProfileToRecordingNamespaceLabel: "default",
		profilerecordingapi.ProfileToContainerLabel:          "redis",
		profilebase.ProfilePartialLabel:                      "true",
	})

	for name, tc := range map[string]struct {
		merge         profilerecordingapi.ProfileMergeStrategy
		containers    []string
		objs          []client.Object
		wantConflicts []string
	}{
		"profile of another namespace": {
			merge:         profilerecordingapi.ProfileMergeContainers,
			containers:    []string{"nginx"},
			objs:          []client.Object{seccompProfile("recording-nginx", recordedBy("other"))},
			wantConflicts: []string{"recording-nginx"},
		},
		"profile which was not recorded": {
			merge:         profilerecordingapi.ProfileMergeContainers,
			containers:    []string{"nginx"},
			objs:          []client.Object{seccompProfile("recording-nginx", nil)},
			wantConflicts: []string{"recording-nginx"},
		},
		"own profile": {
			merge:      profilerecordingapi.ProfileMergeContainers,
			containers: []string{"nginx"},
			objs:       []client.Object{seccompProfile("recording-nginx", recordedBy("default"))},
		},
		"profile recorded before 1.0": {
			merge:      profilerecordingapi.ProfileMergeContainers,
			containers: []string{"nginx"},
			objs: []client.Object{seccompProfile("recording-nginx", map[string]string{
				profilerecordingapi.ProfileToRecordingLabel: "recording",
			})},
		},
		"containers without merge are not known": {
			containers: []string{"nginx"},
			objs:       []client.Object{seccompProfile("recording-nginx", nil)},
		},
		"profile of a tracked replica": {
			objs: []client.Object{
				replica,
				seccompProfile("recording-nginx-abcde", nil),
				// Not recorded by this recording.
				seccompProfile("recording-other-abcde", nil),
			},
			wantConflicts: []string{"recording-nginx-abcde"},
		},
		"partial and merged profile of a tracked replica": {
			merge: profilerecordingapi.ProfileMergeContainers,
			objs: []client.Object{
				replica,
				seccompProfile("recording-nginx-abcde", nil),
				seccompProfile("recording-nginx", recordedBy("other")),
			},
			wantConflicts: []string{"recording-nginx", "recording-nginx-abcde"},
		},
		"merged profile of a partial profile": {
			objs: []client.Object{
				partial,
				seccompProfile("recording-redis", recordedBy("other")),
			},
			wantConflicts: []string{"recording-redis"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recording := statusRecording(profilerecordingapi.ProfileRecorderBpf)
			recording.Spec.MergeStrategy = tc.merge
			recording.Spec.Containers = tc.containers
			recording.Status.ActiveWorkloads = []string{replica.Name}

			_, conflict := reconcileStatus(t, recorderEnv{}, recording, tc.objs...)

			if len(tc.wantConflicts) == 0 {
				require.Equal(t, metav1.ConditionFalse, conflict.Status)
				require.Equal(
					t,
					string(profilerecordingapi.ReasonNoProfileConflict),
					conflict.Reason,
				)

				return
			}

			require.Equal(t, metav1.ConditionTrue, conflict.Status)
			require.Equal(t, string(profilerecordingapi.ReasonProfileOwnedByOther), conflict.Reason)
			require.Contains(t, conflict.Message, strings.Join(tc.wantConflicts, ", "))
		})
	}
}

func TestShortList(t *testing.T) {
	t.Parallel()

	require.Equal(t, "a, b", shortList([]string{"a", "b"}))
	require.Equal(
		t,
		"a, b, c, d, e and 2 more",
		shortList([]string{"a", "b", "c", "d", "e", "f", "g"}),
	)
}

func TestRecordingStatusPredicate(t *testing.T) {
	t.Parallel()

	old := statusRecording(profilerecordingapi.ProfileRecorderBpf)
	pred := recordingStatusPredicate()

	sameSpec := old.DeepCopy()
	sameSpec.Status.Conditions = []metav1.Condition{common.Available()}
	require.False(t, pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: sameSpec}))

	newGeneration := old.DeepCopy()
	newGeneration.Generation++
	require.True(t, pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: newGeneration}))

	newPod := old.DeepCopy()
	newPod.Status.ActiveWorkloads = []string{"pod"}
	require.True(t, pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: newPod}))
}

func TestStatusMapFunctions(t *testing.T) {
	t.Parallel()

	seccompRecording := statusRecording(profilerecordingapi.ProfileRecorderBpf)
	selinuxRecording := statusRecording(profilerecordingapi.ProfileRecorderLogs)
	selinuxRecording.Name = "recording-selinux"
	selinuxRecording.Spec.Kind = profilerecordingapi.ProfileRecordingKindSelinuxProfile
	otherNamespace := statusRecording(profilerecordingapi.ProfileRecorderBpf)
	otherNamespace.Namespace = "other"

	c := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(seccompRecording, selinuxRecording, otherNamespace).
		Build()
	r := &recordingStatusReconciler{client: c, log: logr.Discard()}

	keys := func(requests []reconcile.Request) []string {
		names := make([]string, 0, len(requests))
		for _, req := range requests {
			names = append(names, req.String())
		}

		return names
	}

	require.ElementsMatch(t,
		[]string{"default/recording", "default/recording-selinux", "other/recording"},
		keys(r.allRecordings(t.Context(), nil)))
	require.ElementsMatch(t,
		[]string{"other/recording"},
		keys(r.recordingsInNamespace(t.Context(), namespaceObject("other", nil))))
	require.ElementsMatch(t,
		[]string{"default/recording", "other/recording"},
		keys(r.recordingsWritingProfile(profilerecordingapi.ProfileRecordingKindSeccompProfile)(
			t.Context(), seccompProfile("recording-selinux-nginx", nil))))
	require.ElementsMatch(t,
		[]string{"default/recording-selinux"},
		keys(r.recordingsWritingProfile(profilerecordingapi.ProfileRecordingKindSelinuxProfile)(
			t.Context(), seccompProfile("recording-selinux-nginx", nil))))
	require.Empty(t,
		r.recordingsWritingProfile(profilerecordingapi.ProfileRecordingKindSeccompProfile)(
			t.Context(), seccompProfile("unrelated", nil)))
}

func TestLabelsChanged(t *testing.T) {
	t.Parallel()

	pred := labelsChanged()
	old := namespaceObject("ns", nil)
	labeled := namespaceObject("ns", map[string]string{bindata.EnableRecordingLabel: ""})

	require.False(t, pred.Create(event.CreateEvent{Object: old}))
	require.False(t, pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: old}))
	require.True(t, pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: labeled}))
}
