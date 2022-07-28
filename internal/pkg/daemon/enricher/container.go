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
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"

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

	problematicContainerLabelKey = "spo.x-k8s.io/had-denials"
)

var errContainerIDEmpty = errors.New("container ID is empty")

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;patch;update

func (e *Enricher) getContainerInfo(
	nodeName, targetContainerID string,
) (*types.ContainerInfo, error) {
	// Check the cache first
	item := e.infoCache.Get(targetContainerID)
	if item != nil {
		return item.Value(), nil
	}

	if err := e.populateContainerPodCache(nodeName, targetContainerID); err != nil {
		return nil, fmt.Errorf("get container info for pods: %w", err)
	}

	item = e.infoCache.Get(targetContainerID)
	if item != nil {
		return item.Value(), nil
	}

	return nil, errors.New("no container info for container ID")
}

func (e *Enricher) populateContainerPodCache(
	nodeName, targetContainerID string,
) error {
	containerRetryBackoff := wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
	}

	ctxwithTimeout, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()

	return util.RetryEx(
		&containerRetryBackoff,
		func() (retryErr error) {
			pods, err := e.impl.ListPods(ctxwithTimeout, e.clientset, nodeName)
			if err != nil {
				return fmt.Errorf("list node %s's pods: %w", nodeName, err)
			}

			eg, ctx := errgroup.WithContext(ctxwithTimeout)

			for p := range pods.Items {
				pod := &pods.Items[p]
				e.populateCacheEntryForContainer(ctx, targetContainerID, pod, eg)
			}

			if werr := eg.Wait(); werr != nil {
				return werr
			}

			return nil
		},
		func(inErr error) bool {
			return errors.Is(inErr, errContainerIDEmpty)
		},
	)
}

func (e *Enricher) populateCacheEntryForContainer(
	_ context.Context, targetContainerID string, pod *v1.Pod, eg *errgroup.Group,
) {
	eg.Go(func() (errorToRetry error) {
		// nolint:gocritic // This is what we expect and want
		statuses := append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...)

		for c := range statuses {
			containerStatus := statuses[c]
			containerID := containerStatus.ContainerID
			containerName := containerStatus.Name

			if containerID == "" {
				// This just means the container is still being created
				// We can come back to this later
				idemptyErr := e.handleContainerIDEmpty(pod.Name, containerName, &containerStatus)
				if errors.Is(idemptyErr, errContainerIDEmpty) {
					errorToRetry = idemptyErr
					continue
				}
				return idemptyErr
			}

			rawContainerID := util.ContainerIDRegex.FindString(containerID)
			if rawContainerID == "" {
				e.logger.Info(
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

			if e.labelDenials && rawContainerID == targetContainerID {
				e.logger.Info("labeling problematic container", "containerID", containerID,
					"podNamespace", pod.Namespace, "podName", pod.Name)
				e.labelPodDenials(context.TODO(), info.ContainerName, pod.DeepCopy(), e.logger)
			}

			// Update the cache
			e.infoCache.Set(rawContainerID, info, ttlcache.DefaultTTL)
		}

		return errorToRetry
	})
}

func (e *Enricher) handleContainerIDEmpty(podName, containerName string, containerStatus *v1.ContainerStatus) error {
	if containerStatus.State.Waiting != nil &&
		(containerStatus.State.Waiting.Reason == "ContainerCreating" ||
			containerStatus.State.Waiting.Reason == "PodInitializing") {
		e.logger.Info(
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

func (e *Enricher) labelPodDenials(
	ctx context.Context, containerName string, pod *v1.Pod, l logr.Logger,
) {
	// verify if we need to label or if the label is already there
	if labels := pod.GetLabels(); labels != nil {
		if _, ok := labels[problematicContainerLabelKey]; ok {
			return
		}
	}

	containerRetryBackoff := wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
	}

	if err := util.RetryEx(
		&containerRetryBackoff,
		func() (retryErr error) {
			return e.impl.LabelPodDenials(ctx, e.clientset, pod)
		},
		func(inErr error) bool {
			return !kerrors.IsNotFound(inErr)
		},
	); err != nil {
		l.Error(
			err, "unable to patch container to mark it as problematic",
			"pod.Namespace", pod.GetNamespace(), "pod.Name", pod.GetName(),
			"containerName", containerName,
		)
	}
}
