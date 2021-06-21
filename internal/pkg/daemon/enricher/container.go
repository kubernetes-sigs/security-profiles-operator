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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	crioCgroupRegex = `\/.+-([a-f0-9]+)`
	crioPrefix      = "cri-o://"
)

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;

func getNodeContainers(logger logr.Logger, nodeName string) (map[string]containerInfo, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "get in-cluster config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "load in-cluster config")
	}

	containers := make(map[string]containerInfo)
	err = util.Retry(
		func() (retryErr error) {
			pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
				FieldSelector: "spec.nodeName=" + nodeName,
			})
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

					rawContainerID, err := containerIDRaw(containerID)
					if err != nil {
						logger.Error(
							err, "unable to get container ID",
							"containerName", pod.Name,
						)
						continue
					}

					containers[rawContainerID] = containerInfo{
						PodName:       pod.Name,
						ContainerName: containerStatus.Name,
						Namespace:     pod.Namespace,
						ContainerID:   rawContainerID,
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

func containerIDRaw(containerID string) (string, error) {
	if strings.Contains(containerID, crioPrefix) {
		return strings.TrimPrefix(containerID, crioPrefix), nil
	}

	return "", errors.Wrap(errUnsupportedContainerRuntime, containerID)
}

func getContainerID(processID int) (string, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", processID)
	file, err := os.Open(filepath.Clean(cgroupFile))
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

func extractID(cgroup string) string {
	containerIDRegex := regexp.MustCompile(crioCgroupRegex)
	capture := containerIDRegex.FindStringSubmatch(cgroup)
	if len(capture) > 1 {
		return capture[1]
	}

	return ""
}
