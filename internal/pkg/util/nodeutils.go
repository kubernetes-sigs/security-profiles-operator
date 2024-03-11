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

package util

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
)

func GetDynamicClient() (dynamic.Interface, error) {
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("get in-cluster config: %w", err)
	}

	// Create a dynamic client for working with nodes
	dynamicClient, err := dynamic.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("load dynamic client: %w", err)
	}
	return dynamicClient, nil
}

func GetNodeList(ctx context.Context) ([]string, error) {
	dynamicClient, err := GetDynamicClient()
	if err != nil {
		return nil, err
	}
	// Specify the resource (nodes) and namespace
	nodeResource := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}

	// List the nodes (using the dynamic client)
	nodeList, err := dynamicClient.Resource(nodeResource).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Extract node names
	nodeNames := make([]string, 0, len(nodeList.Items))
	for _, item := range nodeList.Items {
		var node map[string]interface{}
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &node)
		if err != nil {
			return nil, err
		}
		nodeName, _, err := unstructured.NestedString(node, "metadata", "name")
		if err != nil {
			return nil, err
		}
		nodeNames = append(nodeNames, nodeName)
	}

	return nodeNames, nil
}

func FinalizersMatchCurrentNodes(ctx context.Context,
	nodeStatusList *statusv1alpha1.SecurityProfileNodeStatusList,
) (bool, error) {
	// Obtain a list of current node names through a Kubernetes API call
	currentNodeNames, err := GetNodeList(ctx)
	if err != nil {
		return false, err
	}

	for i := range nodeStatusList.Items {
		nodeStatus := &nodeStatusList.Items[i]
		if !StringInSlice(currentNodeNames, nodeStatus.NodeName) {
			// We've found a node that doesn't exist anymore
			return false, nil
		} else {
			continue
		}
	}
	return true, nil
}

func StringInSlice(list []string, str string) bool {
	for _, item := range list {
		if strings.Contains(item, str) {
			return true
		}
	}
	return false
}
