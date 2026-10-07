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

// Package podindex watches the pods of a node and finds the pod of a container
// by its ID, for the daemons which see the processes of containers and need to
// know which pod they belong to.
package podindex

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// containerIDIndex is the name of the index from container IDs to pods.
const containerIDIndex = "containerID"

// ListerWatcher lists and watches the pods an Index keeps.
type ListerWatcher = cache.ListerWatcher

// ErrNotFound is returned by Lookup if no pod of the node has the container.
var ErrNotFound = errors.New("container not found in the pods of the node")

// Index keeps the pods of a node, indexed by the IDs of their init, regular
// and ephemeral containers. The pods it returns are shared and must not be
// modified.
type Index struct {
	informer cache.SharedIndexInformer

	mu sync.Mutex
	// changed is closed and replaced whenever a pod got added or updated.
	changed chan struct{}
}

// NewListerWatcher returns a ListerWatcher for the pods of the node.
func NewListerWatcher(client kubernetes.Interface, nodeName string) *cache.ListWatch {
	selector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	return &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = selector

			return client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = selector

			return client.CoreV1().Pods(metav1.NamespaceAll).Watch(ctx, options)
		},
	}
}

// New returns an Index of the pods listed and watched with lw, usually the
// one of NewListerWatcher. It is empty until Run is called.
func New(lw ListerWatcher) (*Index, error) {
	informer := cache.NewSharedIndexInformerWithOptions(
		lw, &corev1.Pod{}, cache.SharedIndexInformerOptions{
			Indexers:          cache.Indexers{containerIDIndex: indexByContainerID},
			ObjectDescription: "node pods",
		},
	)

	if err := informer.SetTransform(dropManagedFields); err != nil {
		return nil, fmt.Errorf("set pod transform: %w", err)
	}

	idx := &Index{
		informer: informer,
		changed:  make(chan struct{}),
	}

	// The informer updates its store before it notifies the handlers, so a
	// pod is in the index once the signal fires.
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { idx.notify() },
		UpdateFunc: func(any, any) { idx.notify() },
	}); err != nil {
		return nil, fmt.Errorf("add pod event handler: %w", err)
	}

	return idx, nil
}

// Run lists and watches the pods until ctx is done.
func (i *Index) Run(ctx context.Context) {
	i.informer.RunWithContext(ctx)
}

// HasSynced reports whether the initial list of the pods got indexed.
func (i *Index) HasSynced() bool {
	return i.informer.HasSynced()
}

// Changed returns a channel which is closed once a pod got added or updated.
// Take it before reading the index, so that no change in between is missed.
func (i *Index) Changed() <-chan struct{} {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.changed
}

func (i *Index) notify() {
	i.mu.Lock()
	defer i.mu.Unlock()

	close(i.changed)
	i.changed = make(chan struct{})
}

// Get returns the pod which has the container with the ID, without waiting.
func (i *Index) Get(containerID string) (*corev1.Pod, bool) {
	objs, err := i.informer.GetIndexer().ByIndex(containerIDIndex, containerID)
	if err != nil {
		// Only fails for an unknown index.
		return nil, false
	}

	for _, obj := range objs {
		if pod, ok := obj.(*corev1.Pod); ok {
			return pod, true
		}
	}

	return nil, false
}

// lookupRecheckInterval is how often Lookup checks whether it still has to
// wait for a container, besides when a pod changes. The index does not notify
// once it synced or a pod got deleted.
const lookupRecheckInterval = 250 * time.Millisecond

// Lookup returns the pod which has the container with the ID. A container
// which is not in the index yet, because the kubelet did not report its ID in
// the pod status yet, is waited for until ctx is done. It fails with
// ErrNotFound then.
//
// It only waits while the index did not sync yet or while a pod of the node
// has a container which is being created or restarted, see
// ContainersPending. Otherwise the container does not belong to a pod, like
// one which is not managed by Kubernetes, and it fails right away. A container
// which starts before the pod of it shows up in the index at all, because the
// watch lags behind the kubelet, is not waited for either.
func (i *Index) Lookup(ctx context.Context, containerID string) (*corev1.Pod, error) {
	changed := i.Changed()

	pod, wait := i.find(containerID)
	if pod != nil || !wait {
		return pod, notFound(pod, containerID)
	}

	recheck := time.NewTicker(lookupRecheckInterval)
	defer recheck.Stop()

	for {
		select {
		case <-changed:
		case <-recheck.C:
		case <-ctx.Done():
			return nil, notFound(nil, containerID)
		}

		changed = i.Changed()

		pod, wait = i.find(containerID)
		if pod != nil || !wait {
			return pod, notFound(pod, containerID)
		}
	}
}

// find returns the pod which has the container with the ID, or whether the
// container may still show up.
func (i *Index) find(containerID string) (pod *corev1.Pod, wait bool) {
	if pod, ok := i.Get(containerID); ok {
		return pod, false
	}

	if !i.HasSynced() {
		return nil, true
	}

	// The pod may have reported the container since, so one list of the pods
	// tells both whether one has it and whether one has pending containers.
	return findIn(i.informer.GetStore().List(), containerID)
}

// findIn returns the pod of pods which has the container with the ID, or
// whether one of them has a container which is being created or restarted, see
// ContainersPending.
func findIn(pods []any, containerID string) (*corev1.Pod, bool) {
	wait := false

	for _, obj := range pods {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			continue
		}

		if _, ok := ContainerName(pod, containerID); ok {
			return pod, false
		}

		wait = wait || ContainersPending(pod)
	}

	return nil, wait
}

// notFound returns ErrNotFound for the container if no pod was found.
func notFound(pod *corev1.Pod, containerID string) error {
	if pod != nil {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrNotFound, containerID)
}

// ContainersPending reports whether the pod has a container whose ID the
// kubelet may not have reported yet: one without a status or an ID, one which
// waits to be started or restarted, or one which exited and gets restarted.
// The status of a restarted container keeps the ID of the previous one until
// the new one started. A pod which finished or is being deleted starts no
// more containers.
//
// A container which the kubelet restarts before the pod status tells that the
// previous one exited is not detected. The recorder resolves such a container
// later on, see cacheProfilesOfUnresolvedContainers of the bpfrecorder.
func ContainersPending(pod *corev1.Pod) bool {
	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed ||
		pod.DeletionTimestamp != nil {
		return false
	}

	containers := len(pod.Spec.InitContainers) + len(pod.Spec.Containers) +
		len(pod.Spec.EphemeralContainers)
	reported := 0

	for status := range statuses(pod) {
		if containerID(status) == "" || status.State.Waiting != nil ||
			(status.State.Terminated != nil && restarts(pod, status)) {
			return true
		}

		reported++
	}

	return reported < containers
}

// restarts reports whether the kubelet restarts the exited container of the
// status.
func restarts(pod *corev1.Pod, status *corev1.ContainerStatus) bool {
	for i := range pod.Spec.InitContainers {
		container := &pod.Spec.InitContainers[i]
		if container.Name != status.Name {
			continue
		}

		// A sidecar keeps running next to the regular containers.
		if container.RestartPolicy != nil &&
			*container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			return true
		}

		// An init container which succeeded is done.
		if status.State.Terminated.ExitCode == 0 {
			return false
		}

		break
	}

	// An ephemeral container is never restarted.
	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Name == status.Name {
			return false
		}
	}

	switch pod.Spec.RestartPolicy {
	case corev1.RestartPolicyNever:
		return false
	case corev1.RestartPolicyOnFailure:
		return status.State.Terminated.ExitCode != 0
	case corev1.RestartPolicyAlways:
		return true
	default:
		// The API server defaults the policy to Always.
		return true
	}
}

// Pods returns the pods of the node.
func (i *Index) Pods() []*corev1.Pod {
	objs := i.informer.GetStore().List()
	pods := make([]*corev1.Pod, 0, len(objs))

	for _, obj := range objs {
		if pod, ok := obj.(*corev1.Pod); ok {
			pods = append(pods, pod)
		}
	}

	return pods
}

// ContainerIDs returns the IDs of the init, regular and ephemeral containers
// of the pod which the kubelet reported already, without the prefix of the
// container runtime (like "containerd://" or "cri-o://").
func ContainerIDs(pod *corev1.Pod) []string {
	var ids []string

	for status := range statuses(pod) {
		if id := containerID(status); id != "" {
			ids = append(ids, id)
		}
	}

	return ids
}

// ContainerName returns the name of the container with the ID in the pod.
func ContainerName(pod *corev1.Pod, id string) (string, bool) {
	for status := range statuses(pod) {
		if containerID(status) == id {
			return status.Name, true
		}
	}

	return "", false
}

// statuses yields the statuses of the init, regular and ephemeral containers
// of the pod.
func statuses(pod *corev1.Pod) iter.Seq[*corev1.ContainerStatus] {
	return func(yield func(*corev1.ContainerStatus) bool) {
		for _, list := range [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
			pod.Status.EphemeralContainerStatuses,
		} {
			// Index rather than copy: a ContainerStatus is a large struct.
			for i := range list {
				if !yield(&list[i]) {
					return
				}
			}
		}
	}
}

// containerID returns the ID of the container without the prefix of the
// container runtime, or an empty string if the kubelet did not report it yet.
func containerID(status *corev1.ContainerStatus) string {
	if status.ContainerID == "" {
		return ""
	}

	return util.ContainerIDRegex.FindString(status.ContainerID)
}

func indexByContainerID(obj any) ([]string, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, nil
	}

	return ContainerIDs(pod), nil
}

// dropManagedFields drops what nothing looks at, to keep the pods of a busy
// node small.
func dropManagedFields(obj any) (any, error) {
	if pod, ok := obj.(*corev1.Pod); ok {
		pod.ManagedFields = nil
	}

	return obj, nil
}
