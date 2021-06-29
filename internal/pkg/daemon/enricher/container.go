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
	"path/filepath"
	"regexp"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;

func (e *Enricher) getNodeContainers(logger logr.Logger, nodeName string) (map[string]containerInfo, error) {
	config, err := e.impl.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "get in-cluster config")
	}

	clientset, err := e.impl.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "load in-cluster config")
	}

	containers := make(map[string]containerInfo)
	err = util.Retry(
		func() (retryErr error) {
			pods, err := e.impl.ListPods(clientset, nodeName)
			if err != nil {
				return errors.Wrapf(err, "list node %s's pods", nodeName)
			}

			containers = make(map[string]containerInfo)
			for p := range pods.Items {
				pod := pods.Items[p]

				for c := range pod.Status.ContainerStatuses {
					containerStatus := pod.Status.ContainerStatuses[c]
					containerID := containerStatus.ContainerID

					if containerID == "" {
						logger.Info(
							"container ID is still empty, retrying",
							"containerName", containerStatus.Name,
						)
						return errContainerIDEmpty
					}

					rawContainerID := regexID.FindString(containerID)
					if rawContainerID == "" {
						logger.Error(
							err, "unable to get container ID",
							"containerName", pod.Name,
						)
						continue
					}

					containers[rawContainerID] = containerInfo{
						podName:       pod.Name,
						containerName: containerStatus.Name,
						namespace:     pod.Namespace,
						containerID:   rawContainerID,
					}
				}
			}
			return nil
		},
		func(inErr error) bool {
			return errors.Is(inErr, errContainerIDEmpty)
		},
	)
	return containers, err
}

func (e *Enricher) getContainerID(processID int) (string, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", processID)
	file, err := e.impl.Open(filepath.Clean(cgroupFile))
	if err != nil {
		return "", errors.Errorf("could not open cgroup path %s", cgroupFile)
	}
	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if containerID := extractID(scanner.Text()); containerID != "" {
			return containerID, nil
		}
	}

	return "", errors.New("unable to find container ID from cgroup path")
}

// We assume that a container ID has a length of 64.
var regexID = regexp.MustCompile(`[0-9a-f]{64}`)

func extractID(cgroup string) string {
	return regexID.FindString(cgroup)
}
