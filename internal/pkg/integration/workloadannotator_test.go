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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/workloadannotator"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// createSeccompProfile creates a SeccompProfile with the provided name.
func createSeccompProfile(t *testing.T, name string) *seccompprofileapi.SeccompProfile {
	t.Helper()

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccompprofileapi.ActAllow,
		},
	}
	require.NoError(t, k8sClient.Create(t.Context(), profile))

	return profile
}

// seccompPod returns a pod which uses the SeccompProfile in its security
// context.
func seccompPod(namespace, name string, profile *seccompprofileapi.SeccompProfile) *corev1.Pod {
	pod := newPod(namespace, name)
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: new("operator/" + profile.GetProfileFile()),
		},
	}

	return pod
}

// requireActiveWorkloads waits until the profile lists exactly the provided
// workloads and carries the in-use finalizer if the list is not empty.
func requireActiveWorkloads(
	t *testing.T, profile *seccompprofileapi.SeccompProfile, workloads ...string,
) {
	t.Helper()

	eventuallyGet(t, client.ObjectKeyFromObject(profile), &seccompprofileapi.SeccompProfile{},
		func(sp *seccompprofileapi.SeccompProfile) bool {
			active := slices.Sorted(slices.Values(sp.Status.ActiveWorkloads))
			inUse := controllerutil.ContainsFinalizer(sp, util.HasActivePodsFinalizerString)

			return slices.Equal(active, slices.Sorted(slices.Values(workloads))) &&
				inUse == (len(workloads) > 0)
		},
		"waiting for the active workloads of SeccompProfile "+profile.Name+
			" to become ["+strings.Join(workloads, ",")+"]",
	)
}

func TestWorkloadAnnotatorTracksPods(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)
	startManager(t, workloadannotator.NewController(), managerOptions{namespaces: []string{ns}})

	profile := createSeccompProfile(t, uniqueName("tracked", ns))

	pod := seccompPod(ns, "web", profile)
	require.NoError(t, k8sClient.Create(t.Context(), pod))
	requireActiveWorkloads(t, profile, ns+"/web")

	// A second pod using the profile gets added to the list.
	other := seccompPod(ns, "db", profile)
	require.NoError(t, k8sClient.Create(t.Context(), other))
	requireActiveWorkloads(t, profile, ns+"/db", ns+"/web")

	// The profile is released once the last pod is gone.
	deletePod(t, pod)
	requireActiveWorkloads(t, profile, ns+"/db")

	deletePod(t, other)
	requireActiveWorkloads(t, profile)
}

func TestWorkloadAnnotatorPodCreatedBeforeProfile(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)
	startManager(t, workloadannotator.NewController(), managerOptions{namespaces: []string{ns}})

	// The pod references a profile which does not exist yet. The watch of
	// the profiles maps the profile creation to the pods using it.
	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: uniqueName("late", ns)},
		Spec:       seccompprofileapi.SeccompProfileSpec{DefaultAction: seccompprofileapi.ActAllow},
	}
	require.NoError(t, k8sClient.Create(t.Context(), seccompPod(ns, "early", profile)))

	require.NoError(t, k8sClient.Create(t.Context(), profile))
	requireActiveWorkloads(t, profile, ns+"/early")
}

func TestWorkloadAnnotatorPodReplacement(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)
	startManager(t, workloadannotator.NewController(), managerOptions{namespaces: []string{ns}})

	oldProfile := createSeccompProfile(t, uniqueName("old", ns))
	newProfile := createSeccompProfile(t, uniqueName("new", ns))

	pod := seccompPod(ns, "sts-0", oldProfile)
	require.NoError(t, k8sClient.Create(t.Context(), pod))
	requireActiveWorkloads(t, oldProfile, ns+"/sts-0")

	// Replace the pod by one with the same name and another profile, like
	// a StatefulSet does after a spec change.
	oldUID := pod.GetUID()
	deletePod(t, pod)

	replacement := seccompPod(ns, "sts-0", newProfile)
	require.NoError(t, k8sClient.Create(t.Context(), replacement))
	require.NotEqual(t, oldUID, replacement.GetUID())

	requireActiveWorkloads(t, newProfile, ns+"/sts-0")
	requireActiveWorkloads(t, oldProfile)
}

func TestWorkloadAnnotatorIgnoresPodStatusUpdates(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	ns := newNamespace(t)
	gets := startManager(
		t, workloadannotator.NewController(), managerOptions{namespaces: []string{ns}},
	)

	profile := createSeccompProfile(t, uniqueName("status", ns))

	pod := seccompPod(ns, "flappy", profile)
	require.NoError(t, k8sClient.Create(t.Context(), pod))
	requireActiveWorkloads(t, profile, ns+"/flappy")

	key := client.ObjectKeyFromObject(pod)

	require.Eventually(t, func() bool { return gets.get(key) > 0 }, eventuallyTimeout, tick)

	// Let the reconciles of the creation settle.
	settled := gets.get(key)

	require.Never(t, func() bool {
		current := gets.get(key)
		changed := current != settled
		settled = current

		return changed
	}, quietPeriod, tick, "the pod creation keeps getting reconciled")

	before := gets.get(key)

	// Flap the readiness of the pod like the kubelet does. None of these
	// updates changes the profiles the pod uses.
	for _, status := range []corev1.ConditionStatus{
		corev1.ConditionFalse, corev1.ConditionTrue, corev1.ConditionFalse,
	} {
		require.NoError(t, k8sClient.Get(t.Context(), key, pod))
		pod.Status.Conditions = []corev1.PodCondition{{
			Type:               corev1.PodReady,
			Status:             status,
			LastTransitionTime: metav1.Now(),
		}}
		require.NoError(t, k8sClient.Status().Update(t.Context(), pod))
	}

	// A label change does not change the profiles either.
	require.NoError(t, k8sClient.Get(t.Context(), key, pod))
	pod.Labels = map[string]string{"flapped": "true"}
	require.NoError(t, k8sClient.Update(t.Context(), pod))

	// The informer delivers the events in order, so once a later pod got
	// reconciled, the updates above passed the predicates already.
	barrier := seccompPod(ns, "barrier", profile)
	require.NoError(t, k8sClient.Create(t.Context(), barrier))
	requireActiveWorkloads(t, profile, ns+"/barrier", ns+"/flappy")

	require.Never(t, func() bool { return gets.get(key) != before },
		quietPeriod, tick, "a pod status or label update triggered a reconcile")
}
