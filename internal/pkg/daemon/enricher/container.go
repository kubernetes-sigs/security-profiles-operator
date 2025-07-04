/*
Copyright 2025 The Kubernetes Authors.

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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// timeout for operations... The number was chosen randomly.
	operationTimeout = 10 * time.Second
	backoffDuration  = 500 * time.Millisecond
	backoffFactor    = 1.5
	backoffSteps     = 10
)

var errContainerIDEmpty = errors.New("container ID is empty")

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

func getContainerInfo(
	ctx context.Context,
	nodeName, targetContainerID string,
	clientSet kubernetes.Interface,
	impl impl,
	infoCache *ttlcache.Cache[string, *types.ContainerInfo],
	logger logr.Logger,
) (*types.ContainerInfo, error) {
	// Check the cache first
	item := infoCache.Get(targetContainerID)
	if item != nil {
		return item.Value(), nil
	}

	if err := populateContainerPodCache(ctx, nodeName, clientSet, impl, infoCache, logger); err != nil {
		return nil, fmt.Errorf("get container info for pods: %w", err)
	}

	item = infoCache.Get(targetContainerID)
	if item != nil {
		return item.Value(), nil
	}

	return nil, errors.New("no container info for container ID")
}

func populateContainerPodCache(
	ctx context.Context,
	nodeName string, clientset kubernetes.Interface, impl impl,
	infoCache *ttlcache.Cache[string, *types.ContainerInfo],
	logger logr.Logger,
) error {
	containerRetryBackoff := wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
	}

	ctxwithTimeout, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	return util.RetryEx(
		&containerRetryBackoff,
		func() (retryErr error) {
			pods, err := impl.ListPods(ctxwithTimeout, clientset, nodeName)
			if err != nil {
				return fmt.Errorf("list node %s's pods: %w", nodeName, err)
			}

			eg, ctx := errgroup.WithContext(ctxwithTimeout)

			for p := range pods.Items {
				pod := &pods.Items[p]
				populateCacheEntryForContainer(ctx, pod, eg, infoCache, logger)
			}

			return eg.Wait()
		},
		func(inErr error) bool {
			return errors.Is(inErr, errContainerIDEmpty)
		},
	)
}

func populateCacheEntryForContainer(
	_ context.Context, pod *v1.Pod, eg *errgroup.Group,
	infoCache *ttlcache.Cache[string, *types.ContainerInfo], logger logr.Logger,
) {
	eg.Go(func() (errorToRetry error) {
		statuses := slices.Concat(pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses, pod.Status.EphemeralContainerStatuses)

		for c := range statuses {
			containerStatus := statuses[c]
			containerID := containerStatus.ContainerID
			containerName := containerStatus.Name

			if containerID == "" {
				// This just means the container is still being created
				// We can come back to this later
				idemptyErr := handleContainerIDEmpty(pod.Name, containerName, &containerStatus, logger)
				if errors.Is(idemptyErr, errContainerIDEmpty) {
					errorToRetry = idemptyErr

					continue
				}

				return idemptyErr
			}

			rawContainerID := util.ContainerIDRegex.FindString(containerID)
			if rawContainerID == "" {
				logger.Info(
					"unable to get container ID",
					"podName", pod.Name,
					"containerName", containerName,
				)

				continue
			}

			recordProfile, ok := pod.Annotations[config.SeccompProfileRecordLogsAnnotationKey+containerName]
			if !ok {
				recordProfile = pod.Annotations[config.SelinuxProfileRecordLogsAnnotationKey+containerName]
			}

			info := &types.ContainerInfo{
				PodName:       pod.Name,
				ContainerName: containerStatus.Name,
				Namespace:     pod.Namespace,
				ContainerID:   rawContainerID,
				RecordProfile: recordProfile,
			}

			// Update the cache
			infoCache.Set(rawContainerID, info, ttlcache.DefaultTTL)
		}

		return errorToRetry
	})
}

func handleContainerIDEmpty(podName, containerName string,
	containerStatus *v1.ContainerStatus, logger logr.Logger,
) error {
	if containerStatus.State.Waiting != nil &&
		(containerStatus.State.Waiting.Reason == "ContainerCreating" ||
			containerStatus.State.Waiting.Reason == "PodInitializing") {
		logger.Info(
			"container ID is still empty, retrying",
			"podName", podName,
			"containerName", containerName,
		)

		return errContainerIDEmpty
	}

	return fmt.Errorf(
		"container ID not found with container state: %v",
		containerStatus.State,
	)
}
