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
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	spoconfig "sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/bindingtracker"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingtracker"
)

const (
	// bindingFinalizer is the finalizer of the bindings with active
	// workloads.
	bindingFinalizer = "active-workload-lock"
	// recordingFinalizer is the finalizer of the recordings with active
	// workloads.
	recordingFinalizer = "active-seccomp-profile-recording-lock"
)

// createBinding creates a ProfileBinding for the pods with the app label.
func createBinding(t *testing.T, namespace, name string) *profilebindingapi.ProfileBinding {
	t.Helper()

	binding := &profilebindingapi.ProfileBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: profilebindingapi.ProfileBindingSpec{
			ProfileRef: profilebindingapi.ProfileRef{
				Kind: profilebindingapi.ProfileBindingKindSeccompProfile,
				Name: "bound-profile",
			},
			Image:       profilebindingapi.SelectAllContainersImage,
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bound"}},
		},
	}
	require.NoError(t, k8sClient.Create(t.Context(), binding))

	return binding
}

// requireBindingWorkloads waits until the binding lists exactly the provided
// workloads and carries its finalizer if the list is not empty.
func requireBindingWorkloads(
	t *testing.T, binding *profilebindingapi.ProfileBinding, workloads ...string,
) {
	t.Helper()

	eventuallyGet(t, client.ObjectKeyFromObject(binding), &profilebindingapi.ProfileBinding{},
		func(pb *profilebindingapi.ProfileBinding) bool {
			return slices.Equal(
				slices.Sorted(slices.Values(pb.Status.ActiveWorkloads)),
				slices.Sorted(slices.Values(workloads)),
			) && controllerutil.ContainsFinalizer(pb, bindingFinalizer) == (len(workloads) > 0)
		},
		"waiting for the active workloads of ProfileBinding "+binding.Name,
	)
}

func TestBindingTrackerTracksAppliedPods(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)
	startManager(t, bindingtracker.NewController(), managerOptions{namespaces: []string{ns}})

	binding := createBinding(t, ns, "binding")

	// The binding webhook records the bindings it applied in an annotation,
	// which the tracker relies on.
	pod := newPod(ns, "bound")
	pod.Labels = map[string]string{"app": "bound"}
	pod.Annotations = map[string]string{profilebindingapi.AppliedBindingsAnnotation: binding.Name}
	require.NoError(t, k8sClient.Create(t.Context(), pod))

	// A pod the webhook did not apply the binding to stays untracked,
	// although it matches the binding.
	unbound := newPod(ns, "unbound")
	unbound.Labels = map[string]string{"app": "bound"}
	require.NoError(t, k8sClient.Create(t.Context(), unbound))

	requireBindingWorkloads(t, binding, ns+"/bound")

	deletePod(t, pod)
	requireBindingWorkloads(t, binding)
}

func TestBindingTrackerReleasesStaleWorkloads(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)

	// A binding which tracks a pod that got deleted while the operator did
	// not run.
	binding := createBinding(t, ns, "stale")
	binding.Status.ActiveWorkloads = []string{ns + "/gone"}
	require.NoError(t, k8sClient.Status().Update(t.Context(), binding))
	require.True(t, controllerutil.AddFinalizer(binding, bindingFinalizer))
	require.NoError(t, k8sClient.Update(t.Context(), binding))

	// The initial listing of the bindings maps the binding to its active
	// workloads, which releases the deleted pod.
	startManager(t, bindingtracker.NewController(), managerOptions{namespaces: []string{ns}})
	requireBindingWorkloads(t, binding)
}

// createRecording creates a ProfileRecording for the pods with the app label.
func createRecording(t *testing.T, namespace, name string) *profilerecordingapi.ProfileRecording {
	t.Helper()

	recording := &profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: profilerecordingapi.ProfileRecordingSpec{
			Kind:        profilerecordingapi.ProfileRecordingKindSeccompProfile,
			Recorder:    profilerecordingapi.ProfileRecorderBpf,
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "recorded"}},
		},
	}
	require.NoError(t, k8sClient.Create(t.Context(), recording))

	return recording
}

// requireRecordingWorkloads waits until the recording lists exactly the
// provided workloads and carries its finalizer if the list is not empty.
func requireRecordingWorkloads(
	t *testing.T, recording *profilerecordingapi.ProfileRecording, workloads ...string,
) {
	t.Helper()

	eventuallyGet(t, client.ObjectKeyFromObject(recording), &profilerecordingapi.ProfileRecording{},
		func(pr *profilerecordingapi.ProfileRecording) bool {
			return slices.Equal(
				slices.Sorted(slices.Values(pr.Status.ActiveWorkloads)),
				slices.Sorted(slices.Values(workloads)),
			) && controllerutil.ContainsFinalizer(pr, recordingFinalizer) == (len(workloads) > 0)
		},
		"waiting for the active workloads of ProfileRecording "+recording.Name,
	)
}

func TestRecordingTrackerTracksRecordedPods(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)
	startManager(t, recordingtracker.NewController(), managerOptions{namespaces: []string{ns}})

	recording := createRecording(t, ns, "recording")

	// The recording webhook annotates the pods it records with values which
	// start with the recording name.
	pod := newPod(ns, "recorded")
	pod.Labels = map[string]string{"app": "recorded"}
	pod.Annotations = map[string]string{
		spoconfig.SeccompProfileRecordBpfAnnotationKey + "ctr": recording.Name + "_ctr_1",
	}
	require.NoError(t, k8sClient.Create(t.Context(), pod))

	// A pod which matches the selector without the annotation, for example
	// because it got created before the recording, is not recorded.
	unrecorded := newPod(ns, "unrecorded")
	unrecorded.Labels = map[string]string{"app": "recorded"}
	require.NoError(t, k8sClient.Create(t.Context(), unrecorded))

	requireRecordingWorkloads(t, recording, "recorded")

	deletePod(t, pod)
	requireRecordingWorkloads(t, recording)
}

func TestRecordingTrackerReleasesStaleWorkloads(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)

	// A recording which tracks a pod that got deleted while the operator
	// did not run.
	recording := createRecording(t, ns, "stale")
	recording.Status.ActiveWorkloads = []string{"gone"}
	require.NoError(t, k8sClient.Status().Update(t.Context(), recording))
	require.True(t, controllerutil.AddFinalizer(recording, recordingFinalizer))
	require.NoError(t, k8sClient.Update(t.Context(), recording))

	// The initial listing of the recordings maps the recording to its
	// active workloads, which releases the deleted pod.
	startManager(t, recordingtracker.NewController(), managerOptions{namespaces: []string{ns}})
	requireRecordingWorkloads(t, recording)
}
