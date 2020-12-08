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

package selinuxpolicy

// NOTE(jaosorior): We can probably use a library for generating names instead
// of using this.
import (

	// #nosec
	hash "crypto/sha1"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
)

// GetPolicyName gets the policy module name in the format that
// we're expecting for parsing.
func GetPolicyName(name, ns string) string {
	return name + "_" + ns
}

// GetPolicyUsage is the representation of how a pod will call this
// SELinux module.
func GetPolicyUsage(name, ns string) string {
	return GetPolicyName(name, ns) + ".process"
}

// GetPolicyK8sName gets the policy name in a format that's OK for k8s names.
func GetPolicyK8sName(name, ns string) string {
	return name + "-" + ns
}

// Remove "." from node names, which are invalid for pod names.
func parseNodeName(name string) string {
	return strings.ReplaceAll(name, ".", "-")
}

// GetInstallerPodName gets the name of the installer pod. Given that the pod names
// can get pretty long, we hash the name so it fits in the space and is also
// unique.
func GetInstallerPodName(name, ns string, node *corev1.Node) string {
	// policy-installer
	parsedNodeName := parseNodeName(node.Name)
	podname := GetPolicyK8sName(name, ns) + "-" + parsedNodeName

	hasher := hash.New()
	if _, err := io.WriteString(hasher, podname); err != nil {
		log.Error(err, "Error hashing pod name")
	}

	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// GetPolicyConfigMapName Gets the configMap name for a given policy.
func GetPolicyConfigMapName(name, ns string) string {
	namePrefix := "policy-for"
	return namePrefix + "-" + GetPolicyK8sName(name, ns)
}

// GetOperatorNamespace gets the namespace that the operator is currently running on.
func GetOperatorNamespace() string {
	// TODO(jaosorior): Get a method to return the current operator
	// namespace.
	//
	// operatorNs, err := k8sutil.GetOperatorNamespace()
	// if err != nil {
	// 	return "security-profiles-operator"
	// }
	// return operatorNs
	return "security-profiles-operator"
}

// SliceContainsString helper function to check if a string is in a slice of strings.
func SliceContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// RemoveStringFromSlice helper function to remove a string from a slice.
func RemoveStringFromSlice(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}

// IgnoreNotFound ignores "NotFound" errors.
func IgnoreNotFound(err error) error {
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

// IgnoreAlreadyExists ignores "AlreadyExists" errors.
func IgnoreAlreadyExists(err error) error {
	if errors.IsAlreadyExists(err) {
		return nil
	}
	return err
}
