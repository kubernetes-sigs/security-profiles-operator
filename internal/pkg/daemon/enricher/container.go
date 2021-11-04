/*
Copyright 2020 The Kubernetes Authors.

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
	"time"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	backoffDuration = 500 * time.Millisecond
	backoffFactor   = 1.5
	backoffSteps    = 10
)

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;

func (e *Enricher) getContainerInfo(
	nodeName, containerID string,
) (*containerInfo, error) {
	// Check the cache first
	if info, err := e.infoCache.Get(
		containerID,
	); !errors.Is(err, ttlcache.ErrNotFound) {
		return info.(*containerInfo), nil
	}

	clusterConfig, err := e.impl.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "get in-cluster config")
	}

	clientset, err := e.impl.NewForConfig(clusterConfig)
	if err != nil {
		return nil, errors.Wrap(err, "load in-cluster config")
	}

	containerRetryBackoff := wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
	}

	errContainerIDEmpty := errors.New("container ID is empty")
	if err := util.RetryEx(
		&containerRetryBackoff,
		func() (retryErr error) {
			pods, err := e.impl.ListPods(clientset, nodeName)
			if err != nil {
				return errors.Wrapf(err, "list node %s's pods", nodeName)
			}

			for p := range pods.Items {
				pod := &pods.Items[p]

				for c := range pod.Status.ContainerStatuses {
					containerStatus := pod.Status.ContainerStatuses[c]
					containerID := containerStatus.ContainerID
					containerName := containerStatus.Name

					if containerID == "" {
						if containerStatus.State.Waiting != nil &&
							containerStatus.State.Waiting.Reason == "ContainerCreating" {
							e.logger.Info(
								"container ID is still empty, retrying",
								"podName", pod.Name,
								"containerName", containerName,
							)
							return errContainerIDEmpty
						}

						return errors.Errorf(
							"container ID not found with container state: %v",
							containerStatus.State,
						)
					}

					rawContainerID := util.ContainerIDRegex.FindString(containerID)
					if rawContainerID == "" {
						e.logger.Error(
							err, "unable to get container ID",
							"podName", pod.Name,
							"containerName", containerName,
						)
						continue
					}

					recordProfile, ok := pod.Annotations[config.SeccompProfileRecordLogsAnnotationKey+containerName]
					if !ok {
						recordProfile = pod.Annotations[config.SelinuxProfileRecordLogsAnnotationKey+containerName]
					}
					info := &containerInfo{
						podName:       pod.Name,
						containerName: containerStatus.Name,
						namespace:     pod.Namespace,
						containerID:   rawContainerID,
						recordProfile: recordProfile,
					}

					// Update the cache
					if err := e.infoCache.Set(rawContainerID, info); err != nil {
						return errors.Wrap(err, "update cache")
					}
				}
			}
			return nil
		},
		func(inErr error) bool {
			return errors.Is(inErr, errContainerIDEmpty)
		},
	); err != nil {
		return nil, errors.Wrap(err, "get container info for pods")
	}

	if info, err := e.infoCache.Get(
		containerID,
	); !errors.Is(err, ttlcache.ErrNotFound) {
		return info.(*containerInfo), nil
	}

	return nil, errors.New("no container info for container ID")
}
