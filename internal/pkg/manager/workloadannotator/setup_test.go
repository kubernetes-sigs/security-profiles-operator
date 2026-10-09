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

package workloadannotator

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func seccompPod(uid types.UID, profile string) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns", UID: uid}}
	if profile != "" {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: new(profile),
			},
		}
	}

	return pod
}

// Only updates which change the profiles in use get reconciled, not the
// status updates of a pod.
func TestPodPredicateUpdate(t *testing.T) {
	t.Parallel()

	const profile = "operator/profile.json"

	withStatus := func(pod *corev1.Pod) *corev1.Pod {
		pod.Status.Phase = corev1.PodRunning
		pod.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}

		return pod
	}

	completed := func(pod *corev1.Pod) *corev1.Pod {
		pod.Status.Phase = corev1.PodSucceeded

		return pod
	}

	withSelinux := func(pod *corev1.Pod) *corev1.Pod {
		pod.Spec.Containers = []corev1.Container{{SecurityContext: &corev1.SecurityContext{
			SELinuxOptions: &corev1.SELinuxOptions{Type: "profile.process"},
		}}}

		return pod
	}

	withAppArmor := func(pod *corev1.Pod) *corev1.Pod {
		pod.Spec.InitContainers = []corev1.Container{{SecurityContext: &corev1.SecurityContext{
			AppArmorProfile: &corev1.AppArmorProfile{
				Type: corev1.AppArmorProfileTypeLocalhost, LocalhostProfile: new("profile"),
			},
		}}}

		return pod
	}

	for name, tc := range map[string]struct {
		oldPod, newPod *corev1.Pod
		want           bool
	}{
		"status update": {
			oldPod: seccompPod("a", profile), newPod: withStatus(seccompPod("a", profile)),
		},
		"no profile": {oldPod: seccompPod("a", ""), newPod: withStatus(seccompPod("a", ""))},
		"replaced pod": {
			oldPod: seccompPod("a", profile), newPod: seccompPod("b", profile), want: true,
		},
		"seccomp profile changed": {
			oldPod: seccompPod("a", profile), newPod: seccompPod("a", "operator/other.json"), want: true,
		},
		"seccomp profile removed": {oldPod: seccompPod("a", profile), newPod: seccompPod("a", "")},
		"selinux type added": {
			oldPod: seccompPod("a", profile), newPod: withSelinux(seccompPod("a", profile)), want: true,
		},
		"apparmor profile added": {
			oldPod: seccompPod("a", profile), newPod: withAppArmor(seccompPod("a", profile)), want: true,
		},
		"pod completed": {
			oldPod: withStatus(seccompPod("a", profile)), newPod: completed(seccompPod("a", profile)), want: true,
		},
		"completed pod updated": {
			oldPod: completed(seccompPod("a", profile)), newPod: completed(seccompPod("a", profile)),
		},
		"pod without profile completed": {
			oldPod: seccompPod("a", ""), newPod: completed(seccompPod("a", "")),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, podPredicate().Update(event.UpdateEvent{
				ObjectOld: tc.oldPod, ObjectNew: tc.newPod,
			}))
		})
	}

	// Other objects are ignored.
	require.False(t, podPredicate().Update(event.UpdateEvent{
		ObjectOld: &corev1.Node{}, ObjectNew: seccompPod("a", profile),
	}))
	require.False(t, podPredicate().Update(event.UpdateEvent{
		ObjectOld: seccompPod("a", profile), ObjectNew: &corev1.Node{},
	}))
}

func TestPodPredicateCreateDelete(t *testing.T) {
	t.Parallel()

	withProfile := seccompPod("a", "operator/profile.json")
	withoutProfile := seccompPod("a", "")

	p := podPredicate()
	require.True(t, p.Create(event.CreateEvent{Object: withProfile}))
	require.False(t, p.Create(event.CreateEvent{Object: withoutProfile}))
	require.True(t, p.Delete(event.DeleteEvent{Object: withProfile}))
	require.False(t, p.Delete(event.DeleteEvent{Object: withoutProfile}))
	require.True(t, p.Generic(event.GenericEvent{Object: withProfile}))
	require.False(t, p.Generic(event.GenericEvent{Object: withoutProfile}))
}

func TestAllContainers(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Containers:     []corev1.Container{{Name: "a"}, {Name: "b"}},
		InitContainers: []corev1.Container{{Name: "init"}},
		EphemeralContainers: []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"},
		}},
	}}

	names := []string{}
	for ctr := range allContainers(pod) {
		names = append(names, ctr.Name)
	}

	require.Equal(t, []string{"a", "b", "init", "debug"}, names)

	// The iteration stops early without visiting the other containers.
	names = names[:0]
	for ctr := range allContainers(pod) {
		names = append(names, ctr.Name)

		if ctr.Name == "b" {
			break
		}
	}

	require.Equal(t, []string{"a", "b"}, names)

	// The containers are not copied.
	for ctr := range allContainers(pod) {
		ctr.Image = "changed"

		break
	}

	require.Equal(t, "changed", pod.Spec.Containers[0].Image)
}

// Completed pods do not use their profiles anymore.
func TestPodIndexSkipsCompletedPods(t *testing.T) {
	t.Parallel()

	index := podIndex(getSeccompProfilesFromPod)
	pod := seccompPod("a", "operator/profile.json")
	require.Equal(t, []string{"operator/profile.json"}, index(pod))

	pod.Status.Phase = corev1.PodFailed
	require.Empty(t, index(pod))
	require.Empty(t, index(&corev1.Node{}))
}

// The profiles get reconciled once the cache has a change of the pods they
// list or of their in-use finalizer, but not for other updates.
func TestProfileWorkloadsPredicate(t *testing.T) {
	t.Parallel()

	profile := func(mutate func(*apparmorprofileapi.AppArmorProfile)) *apparmorprofileapi.AppArmorProfile {
		aa := &apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{Name: "aa"}}
		aa.Status.ActiveWorkloads = []string{"ns/pod"}
		aa.Status.ActiveWorkloadsCount = 1
		mutate(aa)

		return aa
	}

	unchanged := profile(func(*apparmorprofileapi.AppArmorProfile) {})

	for name, tc := range map[string]struct {
		newProfile *apparmorprofileapi.AppArmorProfile
		want       bool
	}{
		"unchanged": {newProfile: profile(func(aa *apparmorprofileapi.AppArmorProfile) {
			aa.Status.Status = "Installed"
		})},
		"pod added": {newProfile: profile(func(aa *apparmorprofileapi.AppArmorProfile) {
			aa.Status.ActiveWorkloads = append(aa.Status.ActiveWorkloads, "ns/other")
		}), want: true},
		"count changed": {newProfile: profile(func(aa *apparmorprofileapi.AppArmorProfile) {
			aa.Status.ActiveWorkloadsCount = 2
		}), want: true},
		"finalizer added": {newProfile: profile(func(aa *apparmorprofileapi.AppArmorProfile) {
			aa.Finalizers = []string{util.HasActivePodsFinalizerString}
		}), want: true},
	} {
		require.Equal(t, tc.want, profileWorkloadsPredicate.Update(event.UpdateEvent{
			ObjectOld: unchanged, ObjectNew: tc.newProfile,
		}), name)
	}

	require.True(t, profileWorkloadsPredicate.Create(event.CreateEvent{Object: unchanged}))
	require.False(t, profileWorkloadsPredicate.Delete(event.DeleteEvent{Object: unchanged}))
}
