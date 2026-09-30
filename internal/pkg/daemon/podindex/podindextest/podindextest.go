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

// Package podindextest provides a fake source of pods for tests of the users
// of the pod index.
package podindextest

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// ListerWatcher lists the pods it was created with and then sends the changes
// made with Add, Modify and Delete. Changes made before the index started
// watching are buffered, up to watch.DefaultChanSize of them.
type ListerWatcher struct {
	pods    []corev1.Pod
	watcher *watch.RaceFreeFakeWatcher
}

// New returns a ListerWatcher which initially lists pods.
func New(pods ...corev1.Pod) *ListerWatcher {
	return &ListerWatcher{
		pods:    pods,
		watcher: watch.NewRaceFreeFake(),
	}
}

// List returns the initial pods.
func (l *ListerWatcher) List(metav1.ListOptions) (runtime.Object, error) {
	list := &corev1.PodList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}}

	for i := range l.pods {
		list.Items = append(list.Items, *l.pods[i].DeepCopy())
	}

	return list, nil
}

// Watch returns the watcher which gets the changes.
func (l *ListerWatcher) Watch(metav1.ListOptions) (watch.Interface, error) {
	return l.watcher, nil
}

// IsWatchListSemanticsUnSupported makes the informer list and watch instead of
// streaming the initial list, which the fake does not support.
func (*ListerWatcher) IsWatchListSemanticsUnSupported() bool {
	return true
}

// Add sends the creation of the pod.
func (l *ListerWatcher) Add(pod *corev1.Pod) {
	l.watcher.Add(pod.DeepCopy())
}

// Modify sends the update of the pod.
func (l *ListerWatcher) Modify(pod *corev1.Pod) {
	l.watcher.Modify(pod.DeepCopy())
}

// Delete sends the deletion of the pod.
func (l *ListerWatcher) Delete(pod *corev1.Pod) {
	l.watcher.Delete(pod.DeepCopy())
}

// Pod returns a pod in the namespace with containers of the names and IDs,
// given in pairs. The IDs get the prefix of containerd, like the kubelet
// reports them. A container with an empty ID is being created.
func Pod(namespace, name string, containers ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
	}

	for i := 0; i+1 < len(containers); i += 2 {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: containers[i]})

		status := corev1.ContainerStatus{Name: containers[i]}
		if containers[i+1] != "" {
			status.ContainerID = "containerd://" + containers[i+1]
			status.State.Running = &corev1.ContainerStateRunning{}
		} else {
			status.State.Waiting = &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}
		}

		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, status)
	}

	return pod
}
