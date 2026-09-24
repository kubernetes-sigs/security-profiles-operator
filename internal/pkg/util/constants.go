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

package util

import "time"

const (
	ErrGetProfile                = "cannot get security profile"
	HasActivePodsFinalizerString = "in-use-by-active-pods"
	DefaultReadHeaderTimeout     = 3 * time.Second
)

const (
	EventTypeNormal  string = "Normal"
	EventTypeWarning string = "Warning"
)

// Actions of the events.k8s.io/v1 events the operator emits. The action says
// what the reporting controller did or failed to do to the regarding object.
const (
	// EventActionInstall is installing a profile on a node.
	EventActionInstall = "Install"
	// EventActionRemove is removing a profile from a node.
	EventActionRemove = "Remove"
	// EventActionUpdate is updating an object, including its status.
	EventActionUpdate = "Update"
	// EventActionRecord is recording a profile from a workload.
	EventActionRecord = "Record"
	// EventActionMerge is merging recorded profiles.
	EventActionMerge = "Merge"
	// EventActionReconcile is a reconciliation that fails as a whole.
	EventActionReconcile = "Reconcile"
	// EventActionMutate is a mutating admission webhook changing a pod.
	EventActionMutate = "Mutate"
)

const (
	// OperatorConfigMap corresponds to the configMap created from deploy/base/profiles.
	OperatorConfigMap = "security-profiles-operator-profile"

	// SelinuxdImageMappingKey is the key in the configMap that contains the mapping
	// between the selinuxd image and the OS version.
	SelinuxdImageMappingKey = "selinuxd-image-mapping.json"

	JsonEnricherLogVolumeSourceJson = "json-enricher-log-volume-source.json"

	JsonEnricherLogVolumeMountPath = "json-enricher-log-volume-mount-path"
)
