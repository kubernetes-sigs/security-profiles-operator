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
	"context"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// nodeKubeletDirs returns the sorted and deduplicated kubelet root
// directories which nodes configure through the kubelet directory label and
// which differ from the default kubelet directory of the operator. The base
// SPOd already mounts the default one. Invalid labels are ignored and reported
// once per node and value as warning event on the given SPOD.
func (r *ReconcileSPOd) nodeKubeletDirs(
	ctx context.Context, spod *spodapi.SecurityProfilesOperatorDaemon,
) ([]string, error) {
	nodes := &metav1.PartialObjectMetadataList{}
	nodes.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("NodeList"))

	if err := r.client.List(
		ctx, nodes, client.HasLabels{config.KubeletDirNodeLabelKey},
	); err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}

	defaultDir := config.KubeletDir()
	dirs := []string{}
	invalid := map[string]string{}

	r.kubeletDirMu.Lock()
	defer r.kubeletDirMu.Unlock()

	for i := range nodes.Items {
		node := &nodes.Items[i]

		dir, ok, err := util.KubeletDirFromNodeLabels(node.Labels)
		if err != nil {
			// The non-root enabler falls back to the default kubelet
			// directory for such nodes, so there is nothing to mount.
			value := node.Labels[config.KubeletDirNodeLabelKey]
			invalid[node.Name] = value

			if reported, ok := r.invalidKubeletDirLabels[node.Name]; !ok || reported != value {
				r.log.Info(
					"Ignoring invalid kubelet directory label",
					"node", node.Name, "error", err.Error(),
				)
				r.record.Eventf(
					spod, util.EventTypeWarning, reasonInvalidKubeletDirLabel,
					"Ignoring kubelet directory label of node %s: %v", node.Name, err,
				)
			}

			continue
		}

		if !ok || dir == defaultDir || slices.Contains(dirs, dir) {
			continue
		}

		dirs = append(dirs, dir)
	}

	// Only keep the nodes which still have an invalid label, so that the map
	// does not grow and a label which becomes invalid again gets reported.
	r.invalidKubeletDirLabels = invalid

	slices.Sort(dirs)

	return dirs, nil
}

// mountedKubeletDirs returns the sorted custom kubelet root directories which
// the given SPOd DaemonSet mounts in addition to the default one.
func mountedKubeletDirs(ds *appsv1.DaemonSet) []string {
	dirs := []string{}

	for i := range ds.Spec.Template.Spec.Volumes {
		volume := &ds.Spec.Template.Spec.Volumes[i]
		if volume.HostPath == nil ||
			!strings.HasPrefix(volume.Name, bindata.KubeletDirVolumeName+"-") ||
			slices.Contains(dirs, volume.HostPath.Path) ||
			util.ValidateKubeletDir(volume.HostPath.Path) != nil {
			continue
		}

		dirs = append(dirs, volume.HostPath.Path)
	}

	slices.Sort(dirs)

	return dirs
}

// kubeletDirsToMount returns the custom kubelet root directories to render
// into the configured SPOd, given the directories which nodes currently
// reference.
//
// Every change of the directories rolls all SPOd pods at once, so removing a
// directory as soon as its last node is gone would restart the SPOd whenever
// an autoscaled node leaves or a label flaps. Directories which the found
// DaemonSet already mounts are therefore kept as long as the SPOd does not
// need an update for another reason, like a new directory or a changed SPOD
// configuration. Such a rollout drops the unreferenced directories again, so
// the set is bounded by the directories referenced at the last rollout.
func kubeletDirsToMount(configured, found *appsv1.DaemonSet, nodeDirs []string) []string {
	dirs := slices.Concat(mountedKubeletDirs(found), nodeDirs)
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)

	retained := configured.DeepCopy()
	addKubeletDirVolumes(&retained.Spec.Template.Spec, dirs)

	if !spodNeedsUpdate(retained, found) {
		return dirs
	}

	return nodeDirs
}

// addKubeletDirVolumes adds a hostPath volume for each of the given kubelet
// root directories and mounts it into the non-root enabler. The DaemonSet
// shares one pod template across all nodes, while the non-root enabler picks
// the kubelet directory of its node at runtime from the node label, so every
// directory configured on any node has to be mounted.
func addKubeletDirVolumes(templateSpec *corev1.PodSpec, dirs []string) {
	nonRootEnabler := &templateSpec.InitContainers[bindata.InitContainerIDNonRootenabler]

	for i, dir := range dirs {
		volume, mount := bindata.KubeletDirVolume(
			fmt.Sprintf("%s-%d", bindata.KubeletDirVolumeName, i+1), dir,
		)
		templateSpec.Volumes = append(templateSpec.Volumes, volume)
		nonRootEnabler.VolumeMounts = append(nonRootEnabler.VolumeMounts, mount)
	}
}

// kubeletDirLabelChanged filters node events down to the ones which may add
// a kubelet directory to mount. Removing a label or deleting a node does not
// roll the SPOd by itself (see kubeletDirsToMount), so these events are
// ignored.
func kubeletDirLabelChanged() predicate.Funcs {
	hasLabel := func(obj client.Object) bool {
		if obj == nil {
			return false
		}

		_, ok := obj.GetLabels()[config.KubeletDirNodeLabelKey]

		return ok
	}

	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool { return hasLabel(e.Object) },
		DeleteFunc: func(event.DeleteEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return false
			}

			oldDir, oldOk := e.ObjectOld.GetLabels()[config.KubeletDirNodeLabelKey]
			newDir, newOk := e.ObjectNew.GetLabels()[config.KubeletDirNodeLabelKey]

			return newOk && (!oldOk || oldDir != newDir)
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// spodsForNode enqueues every SPOD of the operator namespace, which have to
// render the kubelet directory volumes again after a node event.
func (r *ReconcileSPOd) spodsForNode(ctx context.Context, _ client.Object) []reconcile.Request {
	spods := &spodapi.SecurityProfilesOperatorDaemonList{}
	if err := r.client.List(ctx, spods, client.InNamespace(r.namespace)); err != nil {
		r.log.Error(err, "Cannot list SPODs for node event")

		return nil
	}

	requests := make([]reconcile.Request, 0, len(spods.Items))
	for i := range spods.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&spods.Items[i]),
		})
	}

	return requests
}
