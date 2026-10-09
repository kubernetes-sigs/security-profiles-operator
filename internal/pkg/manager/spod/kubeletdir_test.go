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

package spod

import (
	"maps"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func newNode(name, kubeletDirLabel string) *v1.Node {
	node := &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if kubeletDirLabel != "" {
		node.Labels = map[string]string{config.KubeletDirNodeLabelKey: kubeletDirLabel}
	}

	return node
}

func Test_nodeKubeletDirs(t *testing.T) {
	t.Parallel()

	recorder := events.NewFakeRecorder(100)
	r := newTestReconciler()
	r.record = recorder
	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	r.client = fake.NewClientBuilder().WithObjects(
		newNode("default", ""),
		newNode("custom-1", "mnt-resource-kubelet"),
		newNode("custom-2", "mnt-resource-kubelet"),
		newNode("custom-3", "data-kubelet"),
		newNode("k0s", "var-lib-k0s-kubelet"),
		newNode("microk8s", "var-snap-microk8s-common-var-lib-kubelet"),
		newNode("invalid", "..-..-etc"),
		// Kubelets can set the label on their own node, so it must not be
		// able to mount arbitrary host directories on all nodes.
		newNode("cron", "etc-cron.d"),
		newNode("ssh", "root-.ssh"),
		// The default kubelet directory is part of the base SPOd already.
		newNode("default-label", "var-lib-kubelet"),
	).Build()

	wantDirs := []string{
		"/data/kubelet",
		"/mnt/resource/kubelet",
		"/var/lib/k0s/kubelet",
		"/var/snap/microk8s/common/var/lib/kubelet",
	}

	dirs, err := r.nodeKubeletDirs(t.Context(), spod)
	require.NoError(t, err)
	require.Equal(t, wantDirs, dirs)

	recorded := func() []string {
		got := []string{}

		for {
			select {
			case e := <-recorder.Events:
				got = append(got, e)
			default:
				return got
			}
		}
	}

	got := recorded()
	require.Len(t, got, 3)

	for _, node := range []string{"invalid", "cron", "ssh"} {
		require.True(t, slices.ContainsFunc(got, func(e string) bool {
			return strings.HasPrefix(e, "Warning "+reasonInvalidKubeletDirLabel) &&
				strings.Contains(e, "node "+node+":")
		}), "missing event for node %s in %v", node, got)
	}

	// The same invalid labels are not reported again on every reconcile.
	dirs, err = r.nodeKubeletDirs(t.Context(), spod)
	require.NoError(t, err)
	require.Equal(t, wantDirs, dirs)
	require.Empty(t, recorded())

	// A changed invalid value gets reported again.
	cron := &v1.Node{}
	require.NoError(t, r.client.Get(t.Context(), client.ObjectKey{Name: "cron"}, cron))
	cron.Labels[config.KubeletDirNodeLabelKey] = "etc-cron.daily"
	require.NoError(t, r.client.Update(t.Context(), cron))

	_, err = r.nodeKubeletDirs(t.Context(), spod)
	require.NoError(t, err)

	got = recorded()
	require.Len(t, got, 1)
	require.Contains(t, got[0], "node cron:")

	r.client = fake.NewClientBuilder().WithObjects(newNode("default", "")).Build()
	dirs, err = r.nodeKubeletDirs(t.Context(), spod)
	require.NoError(t, err)
	require.Empty(t, dirs)
	require.Empty(t, r.invalidKubeletDirLabels)
}

// Test_kubeletDirsToMount asserts that the SPOd keeps mounting kubelet
// directories which no node references anymore until it rolls for another
// reason, so that nodes leaving or labels flapping do not restart all pods.
func Test_kubeletDirsToMount(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()

	render := func(spec *spodapi.SPODSpec, dirs ...string) *appsv1.DaemonSet {
		t.Helper()

		ds := &appsv1.DaemonSet{}
		ds.Spec.Template.Spec = *renderedPodSpec(t, r, spec, bindata.CAInjectTypeCertManager)
		addKubeletDirVolumes(&ds.Spec.Template.Spec, dirs)

		return ds
	}

	available := appsv1.DaemonSetStatus{
		DesiredNumberScheduled: 3, UpdatedNumberScheduled: 3, NumberAvailable: 3, NumberReady: 3,
	}

	spec := &spodapi.SPODSpec{}
	found := render(spec, "/data/kubelet", "/mnt/resource/kubelet")
	found.Status = available
	require.Equal(t, []string{"/data/kubelet", "/mnt/resource/kubelet"}, mountedKubeletDirs(found))
	require.Empty(t, mountedKubeletDirs(render(spec)))

	withStatus := func(ds *appsv1.DaemonSet) *appsv1.DaemonSet {
		ds.Status = available

		return ds
	}

	// One pod of the SPOd is not available, for example because its node is
	// NotReady or about to leave the cluster.
	partlyAvailable := found.DeepCopy()
	partlyAvailable.Status.NumberAvailable = 2
	partlyAvailable.Status.NumberReady = 2

	// No pod of the SPOd is available, for example because they cannot mount
	// one of the directories.
	unavailable := found.DeepCopy()
	unavailable.Status.NumberAvailable = 0
	unavailable.Status.NumberReady = 0

	// The rollout of the current template stalls, while pods of the previous
	// one are still available.
	stalled := found.DeepCopy()
	stalled.Status.UpdatedNumberScheduled = 1
	stalled.Status.NumberAvailable = 2

	for _, tc := range []struct {
		name     string
		spec     *spodapi.SPODSpec
		found    *appsv1.DaemonSet
		nodeDirs []string
		want     []string
		// dropsInvalid is set if the found SPOd mounts an invalid
		// directory, which mountedKubeletDirs skips.
		dropsInvalid bool
	}{
		{
			name:     "unchanged",
			spec:     spec,
			nodeDirs: []string{"/data/kubelet", "/mnt/resource/kubelet"},
			want:     []string{"/data/kubelet", "/mnt/resource/kubelet"},
		},
		{
			name:     "last node of a directory gone",
			spec:     spec,
			nodeDirs: []string{"/mnt/resource/kubelet"},
			want:     []string{"/data/kubelet", "/mnt/resource/kubelet"},
		},
		{
			name:     "all custom directories gone",
			spec:     spec,
			nodeDirs: []string{},
			want:     []string{"/data/kubelet", "/mnt/resource/kubelet"},
		},
		{
			name:     "new directory drops the unreferenced ones",
			spec:     spec,
			nodeDirs: []string{"/mnt/resource/kubelet", "/other/kubelet"},
			want:     []string{"/mnt/resource/kubelet", "/other/kubelet"},
		},
		{
			name:     "configuration change drops the unreferenced ones",
			spec:     &spodapi.SPODSpec{Verbosity: 1},
			nodeDirs: []string{"/mnt/resource/kubelet"},
			want:     []string{"/mnt/resource/kubelet"},
		},
		{
			name:     "partly available pods keep the unreferenced ones",
			spec:     spec,
			found:    partlyAvailable,
			nodeDirs: []string{"/mnt/resource/kubelet"},
			want:     []string{"/data/kubelet", "/mnt/resource/kubelet"},
		},
		{
			name:     "stalled rollout drops the unreferenced ones",
			spec:     spec,
			found:    stalled,
			nodeDirs: []string{"/mnt/resource/kubelet"},
			want:     []string{"/mnt/resource/kubelet"},
		},
		{
			name:     "unavailable pods drop the unreferenced ones",
			spec:     spec,
			found:    unavailable,
			nodeDirs: []string{"/mnt/resource/kubelet"},
			want:     []string{"/mnt/resource/kubelet"},
		},
		{
			name:     "unavailable pods keep the referenced ones",
			spec:     spec,
			found:    unavailable,
			nodeDirs: []string{"/data/kubelet", "/mnt/resource/kubelet"},
			want:     []string{"/data/kubelet", "/mnt/resource/kubelet"},
		},
		{
			// Mounted by a version which accepted it, it gets dropped even
			// while the pods are available.
			name:         "directory which is no longer valid",
			spec:         spec,
			found:        withStatus(render(spec, "/mnt/resource/kubelet", "/var/lib/kubelet/cpu_manager_state/kubelet")),
			nodeDirs:     []string{"/mnt/resource/kubelet"},
			want:         []string{"/mnt/resource/kubelet"},
			dropsInvalid: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			found := found
			if tc.found != nil {
				found = tc.found
			}

			configured := render(tc.spec)
			dirs, needsUpdate := kubeletDirsToMount(configured, found, tc.nodeDirs)
			require.Equal(t, tc.want, dirs)

			addKubeletDirVolumes(&configured.Spec.Template.Spec, dirs)
			require.Equal(t, tc.want, mountedKubeletDirs(configured))

			// The returned update decision matches the rendered SPOd, so
			// the reconciler does not have to compare it a second time.
			require.Equal(t, spodNeedsUpdate(configured, found), needsUpdate)

			// Keeping the directories must not cause an update loop.
			if slices.Equal(tc.want, mountedKubeletDirs(found)) &&
				tc.spec == spec && !tc.dropsInvalid {
				require.False(t, needsUpdate)
			} else {
				require.True(t, needsUpdate)
			}
		})
	}
}

// Test_getConfiguredSPOdKubeletDirVolumes asserts that the SPOd mounts only
// the kubelet directories into the non-root enabler, and that changing the
// set of kubelet directories rolls the DaemonSet.
func Test_getConfiguredSPOdKubeletDirVolumes(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()

	render := func(dirs ...string) *v1.PodSpec {
		t.Helper()

		podSpec := renderedPodSpec(t, r, &spodapi.SPODSpec{}, bindata.CAInjectTypeCertManager)
		addKubeletDirVolumes(podSpec, dirs)

		return podSpec
	}

	hostPaths := func(podSpec *v1.PodSpec) map[string]string {
		paths := map[string]string{}

		for i := range podSpec.Volumes {
			if hp := podSpec.Volumes[i].HostPath; hp != nil {
				paths[podSpec.Volumes[i].Name] = hp.Path
			}
		}

		return paths
	}

	base := render()
	require.NotContains(t, hostPaths(base), "host-root-volume")
	require.NotContains(t, slices.Collect(maps.Values(hostPaths(base))), "/")
	// Only the seccomp directories of the kubelet directories are mounted.
	require.Equal(t,
		path.Join(config.KubeletDir(), config.SeccompProfilesFolder),
		hostPaths(base)[bindata.KubeletDirVolumeName],
	)
	require.NotContains(t, slices.Collect(maps.Values(hostPaths(base))), config.KubeletDir())

	custom := render("/data/kubelet", "/mnt/resource/kubelet")
	paths := hostPaths(custom)
	require.Equal(t,
		path.Join(config.KubeletDir(), config.SeccompProfilesFolder),
		paths[bindata.KubeletDirVolumeName],
	)
	require.Equal(t, "/data/kubelet/seccomp", paths[bindata.KubeletDirVolumeName+"-1"])
	require.Equal(t, "/mnt/resource/kubelet/seccomp", paths[bindata.KubeletDirVolumeName+"-2"])

	nonRootEnabler := custom.InitContainers[bindata.InitContainerIDNonRootenabler]
	require.Contains(t, nonRootEnabler.VolumeMounts, v1.VolumeMount{
		Name:      bindata.KubeletDirVolumeName + "-1",
		MountPath: "/host/data/kubelet/seccomp",
	})
	require.Contains(t, nonRootEnabler.VolumeMounts, v1.VolumeMount{
		Name:      bindata.KubeletDirVolumeName + "-2",
		MountPath: "/host/mnt/resource/kubelet/seccomp",
	})

	for _, m := range nonRootEnabler.VolumeMounts {
		require.NotEqual(t, config.HostRoot, m.MountPath)
	}

	asDaemonSet := func(podSpec *v1.PodSpec) *appsv1.DaemonSet {
		ds := &appsv1.DaemonSet{}
		ds.Spec.Template.Spec = *podSpec

		return ds
	}

	require.False(t, spodNeedsUpdate(asDaemonSet(custom), asDaemonSet(custom)))
	require.True(t, spodNeedsUpdate(asDaemonSet(custom), asDaemonSet(base)),
		"a new kubelet directory needs an update")
	require.True(t, spodNeedsUpdate(asDaemonSet(base), asDaemonSet(custom)),
		"a removed kubelet directory needs an update")
	require.True(t, spodNeedsUpdate(
		asDaemonSet(render("/data/kubelet")), asDaemonSet(render("/other/kubelet")),
	), "a changed kubelet directory needs an update")
}

func Test_kubeletDirLabelChanged(t *testing.T) {
	t.Parallel()

	p := kubeletDirLabelChanged()
	plain := newNode("node", "")
	custom := newNode("node", "mnt-resource-kubelet")
	other := newNode("node", "data-kubelet")

	require.False(t, p.Create(event.CreateEvent{Object: plain}))
	require.True(t, p.Create(event.CreateEvent{Object: custom}))
	// Removing a directory lets a SPOd whose pods cannot start drop it.
	require.False(t, p.Delete(event.DeleteEvent{Object: plain}))
	require.True(t, p.Delete(event.DeleteEvent{Object: custom}))
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: custom, ObjectNew: plain}))
	require.False(t, p.Update(event.UpdateEvent{ObjectOld: plain, ObjectNew: plain}))
	require.False(t, p.Update(event.UpdateEvent{ObjectOld: custom, ObjectNew: custom}))
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: plain, ObjectNew: custom}))
	require.True(t, p.Update(event.UpdateEvent{ObjectOld: custom, ObjectNew: other}))
	require.False(t, p.Generic(event.GenericEvent{Object: custom}))
}

func Test_allSPODs(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, spodapi.AddToScheme(scheme))

	r := newTestReconciler()
	r.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&spodapi.SecurityProfilesOperatorDaemon{
			ObjectMeta: metav1.ObjectMeta{Name: config.SPOdName, Namespace: r.namespace},
		},
		&spodapi.SecurityProfilesOperatorDaemon{
			ObjectMeta: metav1.ObjectMeta{Name: config.SPOdName, Namespace: "other"},
		},
	).Build()

	requests := r.allSPODs(t.Context(), newNode("node", "mnt-resource-kubelet"))
	require.Len(t, requests, 1)
	require.Equal(t, client.ObjectKey{Name: config.SPOdName, Namespace: r.namespace},
		requests[0].NamespacedName)
}
