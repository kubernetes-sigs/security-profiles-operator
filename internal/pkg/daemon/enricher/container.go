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
	"slices"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
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

	// missingContainerTimeout is how long a container which was not found in
	// the pod list is not looked up again. The lookup lists every pod on the
	// node and can retry for a while, which stalls the audit log processing.
	// It is shorter than backlogTimeout, so that the lines of a container the
	// pod status just did not list yet are still dispatched.
	missingContainerTimeout = 10 * time.Second
)

var (
	errContainerIDEmpty         = errors.New("container ID is empty")
	errNoContainerInfo          = errors.New("no container info for container ID")
	errContainerRecentlyMissing = errors.New("container ID was not found in the pod list recently")
)

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// defaultContainerBackoff is the retry backoff used when a container ID cannot
// be found in the node's pod list yet.
func defaultContainerBackoff() wait.Backoff {
	return wait.Backoff{
		Duration: backoffDuration,
		Factor:   backoffFactor,
		Steps:    backoffSteps,
	}
}

func newMissingContainerCache() *ttlcache.Cache[string, struct{}] {
	return ttlcache.New(
		ttlcache.WithTTL[string, struct{}](missingContainerTimeout),
		ttlcache.WithCapacity[string, struct{}](maxCacheItems),
		ttlcache.WithDisableTouchOnHit[string, struct{}](),
	)
}

// containerLookup bundles what looking up the pod of a container needs.
type containerLookup struct {
	nodeName  string
	clientSet kubernetes.Interface
	impl      impl
	infoCache *ttlcache.Cache[string, *types.ContainerInfo]
	// missing remembers the containers which were recently not found.
	missing *ttlcache.Cache[string, struct{}]
	logger  logr.Logger
	backoff wait.Backoff
}

func (l *containerLookup) getContainerInfo(
	ctx context.Context, targetContainerID string,
) (*types.ContainerInfo, error) {
	// Check the cache first
	if item := l.infoCache.Get(targetContainerID); item != nil {
		return item.Value(), nil
	}

	if l.missing.Has(targetContainerID) {
		return nil, errContainerRecentlyMissing
	}

	err := l.populateContainerPodCache(ctx, targetContainerID)

	// The error can be about another container, so check again.
	if item := l.infoCache.Get(targetContainerID); item != nil {
		return item.Value(), nil
	}

	l.missing.Set(targetContainerID, struct{}{}, ttlcache.DefaultTTL)

	if err != nil {
		return nil, fmt.Errorf("get container info for pods: %w", err)
	}

	return nil, errNoContainerInfo
}

// populateContainerPodCache caches the containers of all pods on the node. It
// retries while containers are being created, as the target container might
// be one of them, but stops as soon as the target container got cached.
func (l *containerLookup) populateContainerPodCache(
	ctx context.Context, targetContainerID string,
) error {
	ctxwithTimeout, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	backoff := l.backoff

	return util.RetryEx(
		&backoff,
		func() (retryErr error) {
			pods, err := l.impl.ListPods(ctxwithTimeout, l.clientSet, l.nodeName)
			if err != nil {
				return fmt.Errorf("list node %s's pods: %w", l.nodeName, err)
			}

			eg, ctx := errgroup.WithContext(ctxwithTimeout)

			for p := range pods.Items {
				pod := &pods.Items[p]
				populateCacheEntryForContainer(ctx, pod, eg, l.infoCache, l.logger)
			}

			err = eg.Wait()
			if err != nil && l.infoCache.Has(targetContainerID) {
				return nil
			}

			return err
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
			// Index rather than copy: v1.ContainerStatus is a large struct and
			// this runs for every container of every pod on the node.
			containerStatus := &statuses[c]
			containerID := containerStatus.ContainerID
			containerName := containerStatus.Name

			if containerID == "" {
				// A container which is still being created is worth waiting
				// for. Every other one without an ID, for example one whose
				// image cannot be pulled, must not keep the containers after
				// it from being cached.
				if handleContainerIDEmpty(pod.Name, containerName, containerStatus, logger) {
					errorToRetry = errContainerIDEmpty
				}

				continue
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

// handleContainerIDEmpty reports whether a container without an ID is still
// being created, so that looking it up again soon makes sense.
func handleContainerIDEmpty(podName, containerName string,
	containerStatus *v1.ContainerStatus, logger logr.Logger,
) bool {
	if containerStatus.State.Waiting != nil &&
		(containerStatus.State.Waiting.Reason == "ContainerCreating" ||
			containerStatus.State.Waiting.Reason == "PodInitializing") {
		logger.Info(
			"container ID is still empty, retrying",
			"podName", podName,
			"containerName", containerName,
		)

		return true
	}

	logger.V(config.VerboseLevel).Info(
		"Skipping container without ID",
		"podName", podName,
		"containerName", containerName,
		"state", containerStatus.State,
	)

	return false
}
