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

package enricher

import (
	"context"
	"errors"
	"fmt"

	"github.com/jellydator/ttlcache/v3"
	v1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex"
)

var errNoContainerInfo = errors.New("no pod of the node has the container")

// The pods of the node run in every namespace, so the access is cluster scoped.
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// containerInfos tells the pod of a container, from the watched pods of the
// node. The info of a container is kept after its pod got deleted, for the
// audit lines which are read after the container exited.
type containerInfos struct {
	// pods is nil until the enricher runs.
	pods      *podindex.Index
	infoCache *ttlcache.Cache[string, *types.ContainerInfo]
}

func newContainerInfos() *containerInfos {
	return &containerInfos{
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ContainerInfo](maxCacheItems),
		),
	}
}

// watch starts watching the pods of the node until ctx is done.
func (c *containerInfos) watch(ctx context.Context, i impl, nodeName string) error {
	clusterConfig, err := i.InClusterConfig()
	if err != nil {
		return fmt.Errorf("get in-cluster config: %w", err)
	}

	clientset, err := i.NewForConfig(clusterConfig)
	if err != nil {
		return fmt.Errorf("load in-cluster config: %w", err)
	}

	pods, err := podindex.New(i.PodListerWatcher(clientset, nodeName))
	if err != nil {
		return fmt.Errorf("watch pods of node %s: %w", nodeName, err)
	}

	c.pods = pods

	go pods.Run(ctx)

	return nil
}

// get returns the info of the container, without waiting for its pod to
// report it.
func (c *containerInfos) get(containerID string) (*types.ContainerInfo, error) {
	if item := c.infoCache.Get(containerID); item != nil {
		return item.Value(), nil
	}

	if c.pods == nil {
		return nil, errNoContainerInfo
	}

	pod, ok := c.pods.Get(containerID)
	if !ok {
		return nil, errNoContainerInfo
	}

	info := containerInfoOf(pod, containerID)
	c.infoCache.Set(containerID, info, ttlcache.DefaultTTL)

	return info, nil
}

// changed returns a channel which is closed once a pod of the node got added
// or updated. Take it before calling get, so that no change in between is
// missed.
func (c *containerInfos) changed() <-chan struct{} {
	if c.pods == nil {
		// Never closed.
		return nil
	}

	return c.pods.Changed()
}

// containerInfoOf returns the info of the container with the ID in the pod.
func containerInfoOf(pod *v1.Pod, containerID string) *types.ContainerInfo {
	containerName, _ := podindex.ContainerName(pod, containerID)

	recordProfile, ok := pod.Annotations[config.SeccompProfileRecordLogsAnnotationKey+containerName]
	if !ok {
		recordProfile = pod.Annotations[config.SelinuxProfileRecordLogsAnnotationKey+containerName]
	}

	return &types.ContainerInfo{
		PodName:       pod.Name,
		ContainerName: containerName,
		Namespace:     pod.Namespace,
		ContainerID:   containerID,
		RecordProfile: recordProfile,
	}
}
