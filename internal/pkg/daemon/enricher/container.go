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
)

const (
	crioCgroupRegex = `\/.+-([a-f0-9]+)`
	crioPrefix      = "cri-o://"
)

// NOTE(jaosorior): Should this actually be namespace-scoped?
//
// Cluster scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;

func getNodeContainers(nodeName string) (map[string]containerInfo, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("load in-cluster config: %w", err)
	}

	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("list node %s's pods: %w", nodeName, err)
	}

	containers := make(map[string]containerInfo)
	for p := range pods.Items {
		for c := range pods.Items[p].Status.ContainerStatuses {
			containerID, err := containerIDRaw(pods.Items[p].Status.ContainerStatuses[c].ContainerID)
			if err != nil {
				return nil, fmt.Errorf("container id: %w", err)
			}

			containers[containerID] = containerInfo{
				PodName:       pods.Items[p].Name,
				ContainerName: pods.Items[p].Status.ContainerStatuses[c].Name,
				Namespace:     pods.Items[p].Namespace,
				ContainerID:   containerID,
			}
		}
	}
	return containers, nil
}

func containerIDRaw(containerID string) (string, error) {
	if strings.Contains(containerID, crioPrefix) {
		return strings.TrimPrefix(containerID, crioPrefix), nil
	}

	return "", errors.Wrap(errUnsupportedContainerRuntime, containerID)
}

func getContainerID(logger logr.Logger, processID int) string {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", processID)
	file, err := os.Open(filepath.Clean(cgroupFile))
	if err != nil {
		logger.Error(nil, "could not open cgroup", "process-id", processID)
		return ""
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
			return containerID
		}
	}

	return ""
}

func extractID(cgroup string) string {
	containerIDRegex := regexp.MustCompile(crioCgroupRegex)
	capture := containerIDRegex.FindStringSubmatch(cgroup)
	if len(capture) > 1 {
		return capture[1]
	}

	return ""
}
