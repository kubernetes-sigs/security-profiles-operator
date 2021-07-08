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
	"bufio"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/pkg/errors"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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

	errContainerIDEmpty := errors.New("container ID is empty")
	if err := util.Retry(
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
						e.logger.Info(
							"container ID is still empty, retrying",
							"podName", pod.Name,
							"containerName", containerName,
						)
						return errContainerIDEmpty
					}

					rawContainerID := regexID.FindString(containerID)
					if rawContainerID == "" {
						e.logger.Error(
							err, "unable to get container ID",
							"podName", pod.Name,
							"containerName", containerName,
						)
						continue
					}

					recordProfile := pod.Annotations[config.SeccompProfileRecordLogsAnnotationKey+containerName]
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

// We assume that a container ID has a length of 64.
var regexID = regexp.MustCompile(`[0-9a-f]{64}`)

func (e *Enricher) getContainerID(processID int) (string, error) {
	// Check the cache first
	if id, err := e.containerIDCache.Get(
		strconv.Itoa(processID),
	); !errors.Is(err, ttlcache.ErrNotFound) {
		return id.(string), nil
	}

	files, err := ioutil.ReadDir("/proc-host")
	if err != nil {
		return "", errors.Wrap(err, "read host proc")
	}
	for _, f := range files {
		e.logger.Info(f.Name())
	}

	cgroupPath := fmt.Sprintf("/proc-host/%d/cgroup", processID)

	file, err := e.impl.Open(filepath.Clean(cgroupPath))
	if err != nil {
		return "", errors.Wrap(err, "could not open cgroup path")
	}

	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if containerID := regexID.FindString(scanner.Text()); containerID != "" {
			// Update the cache
			if err := e.containerIDCache.Set(
				strconv.Itoa(processID), containerID,
			); err != nil {
				return "", errors.Wrap(err, "update cache")
			}

			return containerID, nil
		}
	}

	return "", errors.New("unable to find container ID from cgroup path")
}
